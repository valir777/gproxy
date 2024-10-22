package main

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "golang.org/x/net/proxy"
)

const proxyListURL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.json"
const geoIPURL = "https://ipwhois.app/json/"
const testURL = "https://www.google.com"
const maxPing = 200 // максимальный пинг, при котором IP считается рабочим

type Proxy struct {
    IP      string `json:"ip"`
    Port    int    `json:"port"`
    Country string `json:"country"`
    ISP     string `json:"isp"`
    Ping    int    `json:"ping"`
}

type GeoIP struct {
    Country string `json:"country"`
    ISP     string `json:"isp"`
}

func fetchProxyList() []Proxy {
    resp, err := http.Get(proxyListURL)
    if err != nil {
        fmt.Println("Ошибка при получении списка прокси:", err)
        return nil
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Ошибка при чтении ответа:", err)
        return nil
    }

    var proxies []Proxy
    err = json.Unmarshal(body, &proxies)
    if err != nil {
        fmt.Println("Ошибка при разборе JSON:", err)
        return nil
    }

    return proxies
}

func getGeoInfo(ip string, defaultCountry string, defaultISP string) (string, string) {
    resp, err := http.Get(geoIPURL + ip)
    if err != nil {
        fmt.Println("Ошибка при получении геоинформации:", err)
        return defaultCountry, defaultISP
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Ошибка при чтении ответа от гео-IP API:", err)
        return defaultCountry, defaultISP
    }

    if len(body) == 0 {
        fmt.Println("Пустой ответ от гео-IP API")
        return defaultCountry, defaultISP
    }

    var geoIP GeoIP
    err = json.Unmarshal(body, &geoIP)
    if err != nil {
        fmt.Println("Ошибка при разборе JSON от гео-IP API:", err)
        fmt.Println("Ответ от гео-IP API:", string(body))
        return defaultCountry, defaultISP
    }

    return geoIP.Country, geoIP.ISP
}

func getPing(ip string) int {
    out, err := exec.Command("ping", "-c", "4", ip).Output()
    if err != nil {
        fmt.Println("Ошибка при выполнении пинга:", err)
        return -1
    }

    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        if strings.Contains(line, "avg") {
            parts := strings.Split(line, "/")
            if len(parts) >= 5 {
                avgPing, _ := strconv.ParseFloat(parts[4], 64)
                return int(avgPing)
            }
        }
    }
    return -1
}

func isProxyWorking(prxy Proxy) bool {
    proxyAddr := fmt.Sprintf("%s:%d", prxy.IP, prxy.Port)
    dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{
        Timeout:   5 * time.Second,
        KeepAlive: 5 * time.Second,
    })
    if err != nil {
        fmt.Println("Ошибка создания SOCKS5 прокси:", err)
        return false
    }

    transport := &http.Transport{
        DialTLS: func(network, addr string) (net.Conn, error) {
            conn, err := dialer.Dial("tcp", addr)
            if err != nil {
                return nil, err
            }
            tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
            return tlsConn, nil
        },
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   10 * time.Second,
    }

    resp, err := client.Get(testURL)
    if err != nil {
        fmt.Println("Ошибка при выполнении HTTPS запроса:", err)
        return false
    }
    defer resp.Body.Close()

    return resp.StatusCode == http.StatusOK
}

func setSystemProxy(prxy Proxy) {
    ip := prxy.IP
    port := prxy.Port
    exec.Command("networksetup", "-setsocksfirewallproxy", "Wi-Fi", ip, strconv.Itoa(port)).Run()
    exec.Command("networksetup", "-setsocksfirewallproxy", "Ethernet", ip, strconv.Itoa(port)).Run()
    fmt.Printf("Подключено к прокси (SOCKS5): %s:%d\n", ip, port)
    country, isp := getGeoInfo(ip, "Неизвестно", "Неизвестно")
    ping := getPing(ip)
    fmt.Printf("Информация о подключении: IP=%s, Port=%d, Ping=%d ms, Страна=%s, Провайдер=%s\n", ip, port, ping, country, isp)
}

func disableSystemProxy() {
    exec.Command("networksetup", "-setsocksfirewallproxystate", "Wi-Fi", "off").Run()
    exec.Command("networksetup", "-setsocksfirewallproxystate", "Ethernet", "off").Run()
    fmt.Println("Системные прокси отключены")
}

func main() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        disableSystemProxy()
        os.Exit(0)
    }()

    allProxies := fetchProxyList()
    workingProxies := []Proxy{}
    var wg sync.WaitGroup
    var mu sync.Mutex

    for _, prxy := range allProxies {
        wg.Add(1)
        go func(prxy Proxy) {
            defer wg.Done()
            if isProxyWorking(prxy) {
                ping := getPing(prxy.IP)
                if ping != -1 && ping <= maxPing {
                    prxy.Ping = ping
                    mu.Lock()
                    workingProxies = append(workingProxies, prxy)
                    mu.Unlock()
                    fmt.Printf("Рабочий прокси %s:%d поддерживает HTTPS\n", prxy.IP, prxy.Port)
                } else {
                    fmt.Printf("Исключен прокси %s:%d (проблема с пингом)\n", prxy.IP, prxy.Port)
                }
            } else {
                fmt.Printf("Исключен прокси %s:%d (не работает или не поддерживает HTTPS)\n", prxy.IP, prxy.Port)
            }
        }(prxy)
    }

    wg.Wait()

    if len(workingProxies) == 0 {
        fmt.Println("Нет доступных прокси, поддерживающих HTTPS")
        return
    }

    selectedProxyIndex := -1
    scanner := bufio.NewScanner(os.Stdin)

    for {
        if selectedProxyIndex == -1 {
            fmt.Println("Доступные прокси:")
            for i, prxy := range workingProxies {
                country, isp := getGeoInfo(prxy.IP, prxy.Country, "")
                fmt.Printf("%d: %s:%d (%s, ping: %d ms, ISP: %s)\n", i+1, prxy.IP, prxy.Port, country, prxy.Ping, isp)
            }

            fmt.Print("Выберите номер прокси: ")
            scanner.Scan()
            choice, err := strconv.Atoi(scanner.Text())
            if err != nil || choice < 1 || choice > len(workingProxies) {
                fmt.Println("Неверный выбор, попробуйте снова")
                continue
            }

            selectedProxy := workingProxies[choice-1]
            setSystemProxy(selectedProxy)
            selectedProxyIndex = choice - 1
        } else {
            fmt.Print("Введите 'change' для смены прокси или 'exit' для выхода: ")
            scanner.Scan()
            input := scanner.Text()
            if input == "change" {
                selectedProxyIndex = -1
            } else if input == "exit" {
                disableSystemProxy()
                os.Exit(0)
            }
        }

        time.Sleep(5 * time.Minute)
    }
}

//made with love for community github.com/valir777