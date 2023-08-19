package signatures

import (
	"bytes"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scorpio-id/pki/internal/config"
)

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

func TestSignX509Certificate(t *testing.T) {
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

	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(response.StatusCode)
}
