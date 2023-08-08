package data

// used to store SANs <-> public key

import (
	"math/big"
	"net"
	"net/url"
	"sync"
)

type SubjectAlternateNameData struct {
	SerialNumber      big.Int
	SubAlternateNames []string
	DNSNames          []string //are probably the SubAlternateNames
	EmailAddresses    []string
	IPAddresses       []net.IP
	URIs              []*url.URL
}
type SubjectAlternateNameDataStore struct {
	SubjectAlternateNameData []SubjectAlternateNameData //names TODO
	mu                       sync.Mutex
}

func NewSubjectAlternateNameDataStore() SubjectAlternateNameDataStore {
	return SubjectAlternateNameDataStore{
		SubjectAlternateNameData: make([]SubjectAlternateNameData, 0),
	}
}

func (s *SubjectAlternateNameDataStore) Add(d SubjectAlternateNameData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.SubjectAlternateNameData = append(s.SubjectAlternateNameData, d)
}

func (s *SubjectAlternateNameDataStore) Delete(san string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for x, v := range s.SubjectAlternateNameData {
		for _, j := range v.SubAlternateNames {
			if san == j {
				s.SubjectAlternateNameData = append(s.SubjectAlternateNameData[:x], s.SubjectAlternateNameData[x+1:]...)
			}
		}
	}
}

//in 'interactions.go' Usercode string was used, tried to do DNSnames to match?
// func (s *SubjectAlternateNameDataStore) Retrieve(san string) (interface{}, error) {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()

// 	for _, v := range s.SubjectAlternateNameData{
// 			if v.DNSNames == DNSNames && !v.IsExpired() {
// 				return v, nil
// 			}
// 	}

// 	return nil, errors.New("no such interaction")
// }

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
