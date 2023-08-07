package data

// used to store SANs <-> public keys

//not sure about Imports for SanStore
import (
	"errors"
	"sync"
	"time"
)

//TALK WITH TEAM ABOUT
	"golang.org/x/text/unicode/rangetable"

//FYI, filling in from interactions.go, let's see how this goes
//MAY HAVE DONE THIS STRUCT AND STRINGS RIGHT
type SubjectAlternateNameData struct {
	SerialNumber BigInt 
	SubAlternateNames []string
	DNSNames []string 
	EmailAddresses []string
	IPAddresses []net.IP
	URIs []*url.URL 
}
type SubjectAlternateNameDataStore struct {
		SubjectAlternateNameData []SubjectAlternateNameData
		mu sync.Mutex 
}

func NewSubjectAlternateNameDataStore() SubjectAlternateNameDataStore {
		return SubjectAlternateNameDataStore{
				SubjectAlternateNameData: make([]SubjectAlternateNameData, 0),
		}
}

func (s *SubjectAlternateNameDataStore) Add(i SubjectAlternateNameData) {
		s.mu.Lock()
		defer s.mu.Unlock()

		for x, v := range s.SubjectAlternateNameData {
				if v == i {
						s.SubjectAlternateNameData = append(s.SubjectAlternateNameData[:x], s.SubjectAlternateNameData[x+1:]...)
						break 
				}
		}
}

//in 'interactions.go' Usercode string was used, tried to do DNSnames to match?
func (s *SubjectAlternateNameDataStore) Retrieve(DNSNames string) (interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, v := range s.SubjectAlternateNameData{
			if v.DNSNames == DNSNames && !v.IsExpired() {
				return v, nil
			}
	}

	return nil, errors.New("no such interaction")
}

//END OF INTERACTIONS.GO, CHECKING WITH TEAM ON NEXT STEPS

// func (s *InteractionStore) RetrieveAuthorization(client string, code string) (interface{}, error) {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()

// 	for _, v := range s.Interactions {
// 		if v.AuthorizationCode == code && v.ClientID == client && !v.IsExpired() {
// 			return v, nil
// 		}
// 	}

// 	return nil, errors.New("no such interaction")
// }