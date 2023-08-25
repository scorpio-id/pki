package signatures

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scorpio-id/pki/internal/config"
)

// this CSR contains SANs test.example.com and *.example.com with no Common Name
const CSR = `-----BEGIN NEW CERTIFICATE REQUEST-----
MIIDZjCCAk4CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbl
UrNyz9CSQCZmomiOjrdVn9HiI+Tg13mtxaPEZCTwmO2w4YYKnNGiwpgTAP7JMr5n
Vd4UvR1LGAiDh+rLoSwB7XHo1SqHKgG+n8x3mwIohfoTla02ucotA9Y16lQaRqHb
rwwbhFRU9DPIL7wtrz6eioDbKJgAsIosa+CFRVL8TlH5ba+5q2pw9sJ7PzGtIdhA
bQKKn0TMqzHE6AA2G5mG6buILl1jHoqjiC1etP5WIWr48B3jzP7H0vUSrpliOF5B
s1VkXcaAIoagkpsyGxZNjEkgRvLAgLscSIxMRgUUGqDv6H/EpAjJGng0BXD6zLCa
ueEu+zKlO8b/GjB5qwECAwEAAaCCAR8wHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5
MDQ1LjIwKwYJKwYBBAGCNxUUMR4wHAIBBQwDTVNJDAlNU0lcYmptMzIMB01NQy5F
WEUwZgYKKwYBBAGCNw0CAjFYMFYCAQEeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMA
dAByAG8AbgBnACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYA
aQBkAGUAcgMBADBqBgkqhkiG9w0BCQ4xXTBbMCoGA1UdEQQjMCGCDSouZXhhbXBs
ZS5jb22CEHRlc3QuZXhhbXBsZS5jb20wHQYDVR0OBBYEFJ50P35zhfEeUVMwWRSH
viBAp6UmMA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQUFAAOCAQEACdJIYKlI
+JigK87BYRy6JAOCVLzGckXm9BGBgd+CrEu+op34LRCHvg9bpUy28oYY2Ewqk3E1
WJtJtaHjYyu5zxjYcfVxm4gJl8e2yUfkOg5UKz/Yi9+yPGITZUOiOWR9pMoAXkLx
5bJTOVR20GqLnsQRPrEnqoxIv/PQL9MPic2Wqrx7ly4SbW606EkGwZ1K0AP7lV1x
4KREot3Ohrv37/m26Jg74qvRBffZoJYHTqPRS6kOPIHlJf0xOg1mS3LSPECUT6OW
H0mUWd2GC0FVhVvPumCwtypDtf5yLBesm/Gx39onIrVDk9frllFH1+ap6MP12VEE
lk+Ij1pb7T4Y7A==
-----END NEW CERTIFICATE REQUEST-----`

// this CSR contains SAN fail.example.com with no common name
const wildcardlessCSR = `-----BEGIN NEW CERTIFICATE REQUEST-----
MIIDXjCCAkYCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANif
M+UWKOlyMuDvGW1jLcFltdN+PoacNarBhSdqsOFGcOgvBuMPQ85j4F4qetDFdJKF
JeOrq02TUrBJr/Ilyj0Zz8IIg0DPijFsxPKP54g7SmNy802YY9Pjb9y8DeuaFFsT
Mauy3Tsk7EJNKpsMgu8xhDzrlkQkBoqgWY2alx7XX/E9jYzDqVD+rtk3yW45Z5jb
P16r0fu6yw5BpJikAiEXY5rJtFd/PT/bg/TZ2ad2YBRSMGkof8fjWz5tEvm87oeW
yZCYPIAmPR7/sN3h4uaK4z6bYrGBtD9DbllZJ7nOUm2W8kFyMbZqgy2Ma2GqDTYo
ZIL3b4yOoObqPdrtvn0CAwEAAaCCARcwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5
MDQ1LjIwQgYJKwYBBAGCNxUUMTUwMwIBBQwPREVTS1RPUC1KU0FTSTVLDBRERVNL
VE9QLUpTQVNJNUtcVXNlcgwHTU1DLkVYRTBLBgkqhkiG9w0BCQ4xPjA8MBsGA1Ud
EQQUMBKCEGZhaWwuZXhhbXBsZS5jb20wHQYDVR0OBBYEFCWAhwWBWWEvv+GdzdHf
RgZJpJqJMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQA
IABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIA
bwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggEBAKTuVesOStd0hR+o7R7m
iXA+/hqj6Jnlk4N2mD5nQc79OA3hWA6TUeks0pbc3dcUIw+U+SaK2guhnGlDgT1x
RLaNfT+ZgUwZAHw3zYv6bPfBdx0d6FF10AIAEaB24xdyDtsVtj8g1IQnxBhNbQGP
im+XzLAej4ujz6LgoonA+QSRCiGbZzztVspUFtfVDoiIJJB5ly6gixvOMK0NWSzN
17n0n8WiFwrx/g6PKYuCYpQICp52mQOx2U2Z2voALqA9azNXZ2R30i/9KT3qHO9P
PsWGJJEkeKMCZ0+rWFVfwcb7uBRB7vLVbvSCv2EhWcCKRxFW9T3S3D8iJoSbo3r/
h8Q=
-----END NEW CERTIFICATE REQUEST-----`

// this CSR contains SAN foo.bar with no common name
const nonPolicyCSR = `-----BEGIN NEW CERTIFICATE REQUEST-----
MIIDVTCCAj0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyM
LCVNvsv6nQoTaT2dN9nJRVxrv3hp2BJxJiKsRaH1Szz/c/6Pj8Wd9oWT9eo9827n
olAJ0smgATXA3YrBvojebnhhWEGT1tS2zjH/YvZX00slmBGAIB3CIa16lDgCRLRR
WwhjBQ46WgY5d8p12h3NqkyahL+1fSBCfiei9aVt5M8vSkR9m0GJRHJm3yPOotdl
fryjHz7GY9v2hrHABynmagY2nFYI07ACCUgB7vI8MvFCR8BxFTZPGd8blACdbjaA
cYevbWh0TcvscYrK8ajjJp0WkrW8JfLTTPhrjDdj22LsyxaRaPx1zvbP0HVfmPj2
UNuj4cJ5CjTqoYeNP4ECAwEAAaCCAQ4wHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5
MDQ1LjIwQgYJKoZIhvcNAQkOMTUwMzASBgNVHREECzAJggdmb28uYmFyMB0GA1Ud
DgQWBBQXVxjpHt957obNMuBOQvhA65SYHDBCBgkrBgEEAYI3FRQxNTAzAgEFDA9E
RVNLVE9QLUpTQVNJNUsMFERFU0tUT1AtSlNBU0k1S1xVc2VyDAdNTUMuRVhFMGYG
CisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0
AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABl
AHIDAQAwDQYJKoZIhvcNAQELBQADggEBAGqFo/1x0LQFPWCFOX7/6PPZBkcdODk6
jsC3ZeO16Au2kKJGXNKvmdqHAEb+k5a7QW0TGGG32hVoE4d9YzjYO/e7B6o3OB9t
rqT4DIMrbsSX1uQyQ+Om8CYwFziMIkvkBKEzO3ijvU8sl24XTdTISPjgNtdFbvf5
YBVrywyL8/p3VymAYgocWqCn64Pk80cIMb2QRNpG8wF2DbnGGFZ9OsnwKDguMsRh
zzqL5pdk9ydNZYA3K/jxXj22tt6+XGTynMjxRZgOD0736IJE2+GJmGuB/YqkX8aF
BFQfuHjwJapnhmYVnDb3uc7KYMXk/6fcU7zk23b+bHIdfMpWRUpaUjE=
-----END NEW CERTIFICATE REQUEST-----`

func TestSignX509Certificate(t *testing.T) {
	// note that test.yml config has *.example.com as allowed SANs
	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 200 {
		b, err := io.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
		}

		log.Print(string(b))
		t.Fatalf("non-200 status code: [%v]", response.StatusCode)
	}
}

func TestSignX509CertificateDuplicateError(t *testing.T) {
	// note that test.yml config has *.example.com as allowed SANs
	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	_, err = client.Do(req)
	if err != nil {
		t.Error(err)
	}

	// send duplicate request and assert error
	buf.Reset()
	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 400 {
		b, err := io.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
		}

		log.Print(string(b))
		t.Fatalf("non-400 status code: [%v]", response.StatusCode)
	}
}

func TestSignX509CertificateWildcardDuplicateError(t *testing.T) {
	// TODO - attempt to sign cert with fail.example.com while *.example.com is already registered
	// create another CSR with desired san fail.example.com

	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	_, err = client.Do(req)
	if err != nil {
		t.Error(err)
	}

	// send request with SAN that fits existing wildcard SAN and asserts error
	buf.Reset()
	writer = multipart.NewWriter(&buf)

	writer.WriteField("csr", wildcardlessCSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err = http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 400 {
		b, err := io.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
		}

		log.Print(string(b))
		t.Fatalf("non-400 status code: [%v]", response.StatusCode)
	}
}

func TestSignX509CertificateWildcardExistsError(t *testing.T) {
	// TODO - attempt to sign cert with fail.example.com while *.example.com is already registered
	// create another CSR with desired san fail.example.com

	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", wildcardlessCSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	_, err = client.Do(req)
	if err != nil {
		t.Error(err)
	}

	// send request with SAN that fits existing wildcard SAN and asserts error
	buf.Reset()
	writer = multipart.NewWriter(&buf)

	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err = http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 400 {
		b, err := io.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
		}

		log.Print(string(b))
		t.Fatalf("non-400 status code: [%v]", response.StatusCode)
	}
}

func TestSignX509CertificateNameAllowedPolicyError(t *testing.T) {
	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", nonPolicyCSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 400 {
		b, err := io.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
		}

		log.Print(string(b))
		t.Fatalf("non-400 status code: [%v]", response.StatusCode)
	}
}
