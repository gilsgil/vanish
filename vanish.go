package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "sync"
    "time"
)

// Lista de provedores de CDN/WAF
var cdnProviders = []string{
    "akamai",
    "imperva",
    "cloudflare",
    "fastly",
    "verizon",
    "stackpath",
    "incapsula",
}

// Gera um User-Agent aleatório simples
func randomUserAgent() string {
    agents := []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)",
        "Mozilla/5.0 (Linux; Android 10)",
    }
    rand.Seed(time.Now().UnixNano())
    return agents[rand.Intn(len(agents))]
}

// checkDNS usa os comandos "host" e "dig" para detectar se um domínio está atrás de um WAF/CDN.
// Retorna true se DETECTOU CDN (ou seja, deve ser filtrado), senão false.
func checkDNS(domain string, verbose bool) bool {
    // Comando "host"
    outputHost, err := exec.Command("host", domain).CombinedOutput()
    if err == nil {
        hostString := strings.ToLower(string(outputHost))
        for _, provider := range cdnProviders {
            if strings.Contains(hostString, provider) {
                if verbose {
                    fmt.Printf("%s (CDN detectado via DNS 'host': %s)\n", domain, strings.Title(provider))
                }
                return true // CDN detectado
            }
        }
    }

    // Comando "dig"
    outputDig, err := exec.Command("dig", domain).CombinedOutput()
    if err == nil {
        digString := strings.ToLower(string(outputDig))
        for _, provider := range cdnProviders {
            if strings.Contains(digString, provider) {
                if verbose {
                    fmt.Printf("%s (CDN detectado via DNS 'dig': %s)\n", domain, strings.Title(provider))
                }
                return true
            }
        }
    }

    return false
}

// checkHTTP faz uma requisição HTTP e verifica os cabeçalhos "Server" e "X-CDN".
// Retorna true se DETECTOU CDN, senão false.
func checkHTTP(domain string, verbose bool) bool {
    client := http.Client{
        Timeout: 5 * time.Second,
    }

    url := "http://" + domain
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return false // não conseguiu criar a requisição, assume não detectado
    }
    req.Header.Set("User-Agent", randomUserAgent())

    resp, err := client.Do(req)
    if err != nil {
        // Erro de conexão ou timeout; não necessariamente indica WAF, então retornamos false
        return false
    }
    defer resp.Body.Close()

    serverHeader := strings.ToLower(resp.Header.Get("Server"))
    xcdnHeader := strings.ToLower(resp.Header.Get("X-CDN"))

    for _, provider := range cdnProviders {
        if strings.Contains(serverHeader, provider) || strings.Contains(xcdnHeader, provider) {
            if verbose {
                fmt.Printf("%s (CDN detectado via HTTP: %s)\n", domain, strings.Title(provider))
            }
            return true
        }
    }

    return false
}

// processDomain faz o fluxo principal de checagem: DNS -> HTTP.
// Retorna true se DOMÍNIO ESTÁ LIMPO (não está atrás de WAF/CDN), ou false se deve ser filtrado.
func processDomain(domain string, verbose bool) bool {
    // Remover ":port" se existir
    if strings.Contains(domain, ":") {
        domain = strings.Split(domain, ":")[0]
    }

    // Primeiro checa via DNS
    if checkDNS(domain, verbose) {
        return false
    }

    // Se não detectou via DNS, checa via HTTP
    if checkHTTP(domain, verbose) {
        return false
    }

    // Se chegou até aqui, não detectou nenhum WAF/CDN
    return true
}

// readDomains auxilia a ler os domínios de arquivo, target ou stdin
func readDomains(listFile, target string) ([]string, error) {
    var domains []string

    switch {
    case listFile != "":
        f, err := os.Open(listFile)
        if err != nil {
            return nil, fmt.Errorf("erro ao abrir arquivo: %v", err)
        }
        defer f.Close()

        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                domains = append(domains, line)
            }
        }
        if err := scanner.Err(); err != nil {
            return nil, err
        }

    case target != "":
        domains = []string{target}

    default:
        // Lê de stdin
        info, err := os.Stdin.Stat()
        if err != nil {
            return nil, err
        }
        if (info.Mode() & os.ModeCharDevice) != 0 {
            return nil, fmt.Errorf("nenhum input de arquivo/lista, target ou stdin")
        }

        reader := bufio.NewReader(os.Stdin)
        for {
            line, err := reader.ReadString('\n')
            if err != nil && err != io.EOF {
                return nil, err
            }
            line = strings.TrimSpace(line)
            if line != "" {
                domains = append(domains, line)
            }
            if err == io.EOF {
                break
            }
        }
    }

    return domains, nil
}

func main() {
    var (
        listFile   string
        singleTgt  string
        concurrency int
        verbose    bool
    )

    flag.StringVar(&listFile, "l", "", "Arquivo contendo a lista de domínios")
    flag.StringVar(&singleTgt, "t", "", "Domínio único para checar")
    flag.IntVar(&concurrency, "c", 10, "Número de threads (goroutines) para execução em paralelo")
    flag.BoolVar(&verbose, "v", false, "Exibir modo verboso (mostrar detecções de WAF/CDN)")
    flag.Parse()

    // Lê domínios de acordo com os parâmetros
    domains, err := readDomains(listFile, singleTgt)
    if err != nil {
        log.Fatalf("Erro ao ler domínios: %v\n", err)
    }

    // Canal para enfileirar os domínios
    domainChan := make(chan string)
    var wg sync.WaitGroup

    // Cria workers
    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for d := range domainChan {
                if processDomain(d, verbose) {
                    // Se não está por trás de CDN, imprime o domínio
                    fmt.Println(d)
                }
            }
        }()
    }

    // Envia domínios para o canal
    go func() {
        for _, d := range domains {
            domainChan <- d
        }
        close(domainChan)
    }()

    // Aguarda todos terminarem
    wg.Wait()
}
