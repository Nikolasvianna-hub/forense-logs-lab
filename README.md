# Relatório: Investigação Forense de Logs & Inteligência de Ameaças

**Ferramentas utilizadas:** PowerShell (`Select-String`, `Get-Content`), CyberChef, VirusTotal
**Arquivos analisados:** `access.log` (19 KB) e `encodedflag.txt` (4 KB), extraídos de `loganalysis-1695809155170.zip`

---

## 1. Metodologia

1. Extração do ZIP com `Expand-Archive` para a pasta `projeto-analise`.
2. Filtro do log pela assinatura de Base64 (`==`):
   ```powershell
   Select-String -Pattern "==" -Path .\access.log
   ```
3. Leitura do arquivo interceptado:
   ```powershell
   Get-Content .\encodedflag.txt
   ```
4. Decodificação dos artefatos no CyberChef.
5. Consulta de reputação e origem dos IPs no VirusTotal (abas *Detection* e *Details*).

---

## 2. Respostas

### 2.1 IP do atacante que tentou extrair a flag Base64

**`212.14.17.145`**

Evidência (linha 62 do `access.log`):

```
212.14.17.145 - - [27/Sep/2023:07:00:53 +0000] "GET /VEhNe0NZQkVSQ0hFRl9XSVpBUkR9== HTTP/1.1" 401 5196
```

Consulta no VirusTotal: país **Polônia (PL)**, AS 8286 (rede acadêmica da Universidade de Szczecin, RIPE NCC), **0/91** fornecedores marcaram como malicioso.

### 2.2 Palavra/frase secreta revelada com `From Base64`

**`THM{CYBERCHEF_WIZARD}`**

Receita usada no CyberChef: *From Base64*, com Input `VEhNe0NZQkVSQ0hFRl9XSVpBUkR9==`. O `==` final não altera o resultado, porque a string já tem tamanho múltiplo de 4.

### 2.3 País e empresa do IP `54.36.115.221` (varredura do `.env`)

| Campo | Valor |
|---|---|
| País | **França (FR)** |
| Empresa | **OVH SAS** (AS 16276) |
| Bloco de rede | 54.36.0.0/14 (RIPE NCC) |
| Detecções | 1/91 malicioso (Webroot); 1 suspeito (Gridinsoft) |
| Community Score | -4 |
| CrowdSec | *Exploitation attempt*, *HTTP Bruteforce*, *HTTP Exploit* |

Comportamento observado no log: várias requisições `GET /.env` e `POST /`, todas com resposta 401 (linhas 13, 14, 35, 36, 44...). O padrão indica varredura automatizada em busca de arquivos de configuração com credenciais. O servidor negou o acesso em todas as tentativas.

### 2.4 Mensagem do `encodedflag.txt`

**Resultado inconclusivo.**

Aplicando `From Base64`, o arquivo decodifica para uma sequência de blocos hexadecimais separados por hífen, por exemplo `08-2E-9A-4B-7FE-610A-3C-8B-...`. Testes realizados sem obter mensagem legível:

- Regex no CyberChef (`THM\{.*?\}`, `[A-Za-z ]{6,}` e a própria flag do item 2.2): sem correspondências.
- Conversão de hexadecimal para texto: bytes aleatórios.
- XOR de 1 byte com todas as chaves possíveis: sem texto legível.
- Operação *Magic* (profundidade 3): só reconheceu a camada de Base64, sem outras codificações.

A entropia baixa (3,71) é coerente com dígitos hexadecimais aleatórios. Como a flag do item 2.2 não aparece nesse arquivo, não a usei como resposta desta pergunta.

---

## 3. Conclusões

- O log registra dois comportamentos distintos: uma requisição isolada que carregava dado em Base64 na URL (`212.14.17.145`) e uma varredura repetida por arquivos sensíveis (`54.36.115.221`, OVH, França).
- Todas as tentativas foram barradas com 401, sem evidência de acesso bem-sucedido no trecho analisado.
- Nota metodológica: o IP `212.14.17.145` pertence a uma rede acadêmica sem histórico de abuso no VirusTotal. Como o log é de um laboratório, ele é tratado aqui apenas como origem da requisição com a flag.

---

## 4. Evidências (anexar)

- [ ] Captura da linha 62 no PowerShell (`Select-String`)
- [ ] CyberChef com `THM{CYBERCHEF_WIZARD}` no Output
- [ ] VirusTotal, aba *Details* de `54.36.115.221` (França / OVH SAS)
- [ ] VirusTotal, abas *Detection* e *Details* de `212.14.17.145`
- [ ] CyberChef com o `encodedflag.txt` decodificado (blocos hexadecimais)
