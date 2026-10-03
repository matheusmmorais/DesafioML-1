# Analisador de Tráfego de Rede

Aplicação em Python que captura pacotes de uma interface de rede, grava os dados em um banco SQLite e exibe estatísticas básicas de tráfego. Roda em Docker.

## O que ela faz

**Captura** (Scapy), por pacote:
- IP de origem
- IP de destino
- Protocolo (TCP, UDP, ICMP, ICMPv6, ARP, etc.)
- Tamanho em bytes

**Estatísticas** (calculadas com SQL sobre o banco):
- Total de pacotes capturados
- Pacotes por protocolo (com porcentagem e bytes)
- Top 5 IPs de origem com mais tráfego
- Top 5 IPs de destino com mais tráfego

**Armazenamento:** todos os pacotes ficam em SQLite, na pasta local `data/` (montada no container), e persistem após o fim da execução.

**Relatório visual:** ao final de cada captura é gerado `data/relatorio.html`, uma página com gráfico de pizza (protocolos), barras (Top 5 origem e destino) e tabelas. Abre em qualquer navegador, sem internet e sem bibliotecas externas.

## Estrutura

```
.
├── analyzer.py          # aplicação
├── requirements.txt     # scapy
├── Dockerfile
├── docker-compose.yml
├── executar_aplicacao.bat  # atalho opcional: duplo clique no Windows
└── data/                # criado na 1ª execução: traffic.db e relatorio.html
```

## Início rápido (1 comando)

Pré-requisito: Docker (Docker Desktop no Windows/Mac). Validado no Windows (Docker Desktop); deve funcionar igual em Mac e Linux. Não exige instalar Python nem Scapy.

```bash
docker compose up --build
```

O que acontece: o container captura pacotes na própria interface durante 20 segundos, **gerando tráfego de teste sozinho** (ping, consultas DNS e requisições HTTP), grava tudo no banco e imprime as estatísticas no terminal. Ao final, os resultados ficam na pasta `data/`:

- `data/relatorio.html`: relatório visual (abrir no navegador)
- `data/traffic.db`: banco SQLite com todos os pacotes

**Atalho (Windows):** dê duplo clique em `executar_aplicacao.bat`. Ele verifica o Docker, constrói e executa a captura (equivalente ao comando acima) e abre o relatório ao final.

Sem Docker Compose:

```bash
docker build -t traffic-analyzer .
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN -v "$PWD/data:/data" traffic-analyzer --demo
```

(No PowerShell, use `${PWD}` no lugar de `$PWD`.)

> O modo `--demo` usa a rede interna do container, por isso funciona igual em qualquer sistema. Para capturar o tráfego real da máquina, veja "Como executar no Linux" abaixo. Se a máquina estiver sem internet, a captura ainda funciona, mas com poucos pacotes (apenas tráfego local, como ARP).

## Teste manual com dois terminais (Windows/Docker Desktop)

No Docker Desktop (Windows/Mac), `network_mode: host` enxerga apenas a rede da VM do Docker. Por isso, o método abaixo usa dois containers que **compartilham a mesma rede**: um captura e o outro gera tráfego de teste. Este foi o procedimento validado.

Pré-requisitos: Docker Desktop em execução (virtualização habilitada na BIOS) e o PowerShell aberto na pasta do projeto.

```powershell
# 1. Construir a imagem (uma vez)
docker build -t traffic-analyzer .

# 2. Baixar a imagem auxiliar usada para gerar tráfego (uma vez)
docker pull alpine
```

**Janela 1 (captura de 60 segundos):**
```powershell
docker run --rm --name sniffer --cap-add NET_RAW --cap-add NET_ADMIN -v "${PWD}/data:/data" traffic-analyzer -i eth0 -t 60
```

**Janela 2 (gera tráfego dentro da mesma rede, enquanto a Janela 1 captura):**
```powershell
docker run --rm --network container:sniffer alpine ping -c 15 8.8.8.8
docker run --rm --network container:sniffer alpine wget -qO- http://example.com
```

Ao final, a Janela 1 exibe as estatísticas e grava `data\relatorio.html` (abra com duplo clique) e `data\traffic.db`.

Para rever depois, sem capturar: `docker run --rm -v "${PWD}/data:/data" traffic-analyzer --report`

### Exemplo de resultado (execução de 60 s)

| Protocolo | Pacotes | Origem do tráfego |
|---|---|---|
| ICMP | 30 | `ping`: 15 pedidos + 15 respostas |
| TCP | 11 | `wget` para example.com |
| ARP | 9 | resolução de endereços na rede local |
| UDP | 4 | consultas DNS |
| IPv6-HopByHop | 5 | mensagens multicast IPv6 geradas pelo sistema (ex.: destino `ff02::16`) |

Total: 59 pacotes (5.8 KB). IPs de destaque: `172.17.0.2` (o próprio container), `8.8.8.8` (alvo do ping), `172.66.147.243` (example.com) e `192.168.65.7` (DNS interno do Docker Desktop).

Prints de uma mesma execução (sessão 14, 222 pacotes) na pasta `prints/`:

- `execucao.png`: saída no terminal
- `relatorio.png`: relatório HTML
- `banco_schema.png`: estrutura do banco (tabelas `packets` e `sessions` e índices), aberto no DB Browser for SQLite
- `banco_dados.png`: tabela `packets` com os pacotes gravados (filtro `session_id = 14`)

## Como executar no Linux

Pré-requisito: Docker e Docker Compose em uma máquina **Linux**.

### 1. Build

```bash
docker compose build
```

### 2. Descobrir o nome da interface

```bash
docker compose run --rm live --list-interfaces
```

### 3. Capturar

```bash
# Captura 30 segundos na interface eth0
docker compose run --rm live -i eth0 -t 30

# Captura 500 pacotes
docker compose run --rm live -i eth0 -c 500

# Só tráfego HTTPS (filtro BPF)
docker compose run --rm live -i eth0 -t 60 -f "tcp port 443"
```

Sem `-t` nem `-c`, a captura segue até `Ctrl+C`. Ao terminar, as estatísticas são exibidas automaticamente.

Dica: para gerar tráfego durante o teste, em outro terminal rode `ping 8.8.8.8` ou `curl https://example.com`.

### 4. Consultar estatísticas depois

```bash
docker compose run --rm live --report              # última sessão
docker compose run --rm live --report --session 2  # sessão específica
docker compose run --rm live --report --all        # todas as sessões
```

### 5. Consultar o banco diretamente

```bash
sqlite3 data/traffic.db "SELECT * FROM packets LIMIT 10;"
```

### Modo offline (sem privilégios de rede)

Útil para testar a lógica com um arquivo `.pcap`:

```bash
docker compose run --rm -v "$PWD:/pcaps" live --pcap /pcaps/captura.pcap
```

### Sem Docker Compose

```bash
docker build -t traffic-analyzer .
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/data:/data" traffic-analyzer -i eth0 -t 30
```

## Opções

| Opção | Descrição |
|---|---|
| `-i, --interface` | Interface de rede (padrão: `eth0`, ou variável `CAPTURE_INTERFACE`) |
| `-c, --count` | Para após N pacotes armazenados |
| `-t, --timeout` | Para após N segundos |
| `-f, --filter` | Filtro BPF |
| `--top` | Tamanho dos rankings (padrão 5) |
| `--pcap` | Lê de arquivo .pcap |
| `--report` | Apenas exibe estatísticas do banco |
| `--session`, `--all` | Escolhe a sessão do relatório |
| `--html` | Caminho do relatório HTML (padrão: `relatorio.html` ao lado do banco) |
| `--demo` | Gera tráfego de teste (ping, DNS, HTTP) durante a captura; 20 s por padrão |
| `--list-interfaces` | Lista interfaces e sai |

## Schema do banco

```sql
sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    interface   TEXT NOT NULL,
    bpf_filter  TEXT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);

packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    captured_at TEXT NOT NULL,      -- ISO 8601, UTC
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    size        INTEGER NOT NULL    -- bytes
);
```

Índices em `(session_id)`, `(session_id, protocol)`, `(session_id, src_ip)` e `(session_id, dst_ip)`, que são exatamente as colunas usadas nos `GROUP BY` das estatísticas.

## Decisões e justificativas

**Python + Scapy.** Sugeridos no enunciado, API simples para dissecar pacotes e ampla adoção em troubleshooting de rede.

**SQLite.** O volume de dados é de um único processo escrevendo localmente, então não há necessidade de um servidor de banco. SQLite não exige serviço extra, o banco é um único arquivo (fácil de inspecionar e copiar) e a aplicação fica com um único container. Se o projeto evoluísse para múltiplos coletores ou consultas concorrentes, a migração natural seria PostgreSQL (o schema é portável).

**Tabela `sessions`.** Cada execução gera uma sessão. Isso evita misturar capturas diferentes nas estatísticas e permite comparar execuções (`--session N`).

**Gravação em lote.** Inserir pacote a pacote com `commit` individual seria o gargalo em tráfego intenso e causaria perda de pacotes. O código acumula em memória e grava em lote (a cada 200 pacotes ou 2 segundos). O flush final também é executado em `Ctrl+C` e em `docker stop` (SIGTERM tratado), então nenhum pacote pendente se perde.

**`store=False` no Scapy.** Os pacotes não são mantidos em memória: cada um é processado e descartado, então a captura roda por longos períodos sem crescer em memória.

**Estatísticas via SQL.** O banco calcula os agregados (`COUNT`, `SUM`, `GROUP BY`), então funcionam também sobre dados já gravados (`--report`) e escalam melhor que contadores em Python.

**"Mais tráfego" = bytes.** O ranking Top 5 ordena por volume em bytes (pacotes como critério de desempate). A tabela também mostra a contagem de pacotes.

**Protocolo pelo número IP.** O protocolo vem do campo `protocol` (IPv4) ou `next header` (IPv6), mapeado para o nome. Isso evita rotular errado um ICMP de erro que carrega um TCP dentro dele. Protocolos desconhecidos aparecem como `OTHER(n)`.

**IPv4, IPv6 e ARP.** IPv6 é tratado igual ao IPv4. ARP não tem camada IP, mas carrega IP de origem e destino, então é registrado como protocolo `ARP`.

**Relatório HTML sem dependências.** Os gráficos são SVG e CSS gerados pelo próprio Python (sem Chart.js ou CDN), então a página funciona offline e não adiciona bibliotecas à imagem Docker. Os dados vêm das mesmas consultas SQL do relatório de texto.

**Frames sem IP ignorados.** STP, LLDP, CDP etc. não têm endereço IP e não se encaixam nos campos exigidos. O programa informa a quantidade ignorada ao final.

**Modo `--demo` (um comando).** Quem avalia o projeto não deveria precisar montar um cenário de teste. O container gera o próprio tráfego (ping, DNS, HTTP) em uma thread separada enquanto captura, então `docker compose up --build` mostra o resultado completo em qualquer sistema.

**Docker com `network_mode: host` e capabilities (serviço `live`).** Para capturar as interfaces reais de uma máquina Linux, o container usa a rede do host. Em vez de `privileged: true`, são concedidas só as capabilities `NET_RAW` e `NET_ADMIN`. O `tcpdump` é instalado na imagem porque o Scapy o usa para compilar filtros BPF.

**Volume `./data:/data`.** O banco sobrevive ao fim do container.

## Limitações

- **Docker Desktop (Windows/Mac):** a captura enxerga apenas a rede do container/VM do Docker, não a placa de rede física do computador. Por isso o teste usa um segundo container gerando tráfego na mesma rede. Para capturar a rede real, execute em Linux ou rode o `analyzer.py` direto no host (requer Npcap no Windows).
- Captura exige privilégios (root ou `NET_RAW`).
- Em redes de altíssimo tráfego, o Scapy (Python) pode perder pacotes; para esse cenário, ferramentas como `tcpdump`/`libpcap` em C seriam mais adequadas.
- Apenas cabeçalhos são analisados. O conteúdo (payload) dos pacotes não é armazenado, por questões de volume e privacidade.

## Próximos passos possíveis

- Exportar para PostgreSQL ou Elasticsearch
- Armazenar portas de origem/destino e flags TCP
- Dashboard em tempo real (Grafana) sobre o banco
- Política de retenção (apagar sessões antigas)
