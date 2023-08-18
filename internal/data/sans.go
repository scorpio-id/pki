package data

// used to store SANs <-> public key

import (
	"fmt"
	"math/big"
	"sync"
)

type SANs struct {
	SerialNumber *big.Int
	Names        []string
}

type SubjectAlternateNameStore struct {
	Data []SANs
	mu   sync.Mutex
}

func NewSubjectAlternateNameStore() SubjectAlternateNameStore {
	return SubjectAlternateNameStore{
		Data: make([]SANs, 0),
	}
}

func (s *SubjectAlternateNameStore) Add(d SANs) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// check to make sure SAN is unique
	// FIXME - for example, if *.example.com is within, don't allow test.example.com
	for _, data := range s.Data {
		for _, san := range data.Names {
			for _, name := range d.Names {
				if name == san {
					return fmt.Errorf("subject alternate name [%v] is already in use", san)
				}
			}
		}
	}

	// check to make sure serial number unique
	for _, data := range s.Data {
		if data.SerialNumber.Cmp(d.SerialNumber) == 0 {
			return fmt.Errorf("serial number [%v] is not unique", d.SerialNumber)
		}
	}

	s.Data = append(s.Data, d)
	return nil
}

func (s *SubjectAlternateNameStore) Delete(san string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for x, v := range s.Data {
		for _, j := range v.Names {
			if san == j {
				s.Data = append(s.Data[:x], s.Data[x+1:]...)
			}
		}
	}
}
