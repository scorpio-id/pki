package data

// used to store SANs <-> public key

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type SANs struct {
	SerialNumber int64
	Names        []string
}

type SubjectAlternateNameStore struct {
	Data []SANs
	mu   sync.Mutex
}

func NewSubjectAlternateNameStore() *SubjectAlternateNameStore {
	return &SubjectAlternateNameStore{
		Data: make([]SANs, 0),
	}
}

func (store *SubjectAlternateNameStore) Add(s SANs) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	// ensure SAN is free
	for _, data := range store.Data {
		for _, san := range data.Names {
			for _, name := range s.Names {
				// FIXME -- removed uniqueness check for demonstration purposes!
				// if name == san && name != "" {
				// 	return fmt.Errorf("subject alternate name [%v] is already in use", san)
				// }

				// if current SAN contains a wildcard create regex and match
				if strings.Contains(san, "*") {
					// ex: *.test.com must become regex .*.test.com
					match, err := regexp.MatchString("."+san, name)
					if err != nil {
						return err
					}

					if match {
						return fmt.Errorf("subject alternate name [%v] is already in use by [%v]", name, san)
					}
				}

				// checks if an existing issued certificate has a SAN under the desired wildcard SAN
				if strings.Contains(name, "*") {
					// ex: *.test.com must become regex .*.test.com
					match, err := regexp.MatchString("."+name, san)
					if err != nil {
						return err
					}

					if match {
						return fmt.Errorf("subject alternate name [%v] is already in use by [%v]", name, san)
					}
				}
			}
		}
	}

	// ensure serial number unique
	for _, san := range store.Data {
		if san.SerialNumber == s.SerialNumber {
			return fmt.Errorf("serial number [%v] is not unique", s.SerialNumber)
		}
	}

	store.Data = append(store.Data, s)
	return nil
}

func (store *SubjectAlternateNameStore) Delete(san string) {
	store.mu.Lock()
	defer store.mu.Unlock()

	for x, v := range store.Data {
		for _, j := range v.Names {
			if san == j {
				store.Data = append(store.Data[:x], store.Data[x+1:]...)
			}
		}
	}
}
