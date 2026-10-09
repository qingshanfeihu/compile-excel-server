#!/usr/bin/env bash
# compile-excel-server 一键安装（macOS / Linux）
#
#   curl -fsSL https://raw.githubusercontent.com/qingshanfeihu/compile-excel-server/main/install.sh | bash
#
# 下载与本机匹配的安装包 → 核对 SHA256SUMS → 先试运行一次 → 切换到新版本 → 在 ~/.local/bin 放 ces 命令。
# 不依赖本机的 Python。中途任何一步失败，原来装的版本都不动。
#
# 目录：<程序根>/versions/<版本>/ 放各个版本，<程序根>/current 是指向当前版本的链接。切换只改链接，
# 正在运行的旧进程继续用它自己的那份文件（保留上一个版本，更早的删掉）。
#
# 选项：
#   --gateway       改装跳板机网关 cexg（只有 Linux x86_64 的安装包），命令是 cexg
#   --from-source   从当前代码目录安装（开发用；建独立的 Python 虚拟环境，不碰系统环境）
#
# 环境变量：
#   CES_VERSION     指定版本（例如 0.2.0）；不设就装最新版
#   CES_REPO        默认 qingshanfeihu/compile-excel-server
#   CES_BIN_DIR     命令放在哪里，默认 ~/.local/bin
#   CES_PREFIX      程序放在哪里，默认 ~/.local/share/compile-excel-server（网关是 ~/.local/share/cexg）
#   CES_DATA_HOME   默认数据目录，默认 ~/ces-data（只建空目录，配置用 ces setup）
#   CES_UPDATE=1    更新模式（ces update 调用时设置）：只报告结果，不打印首次使用说明

set -euo pipefail

REPO="${CES_REPO:-qingshanfeihu/compile-excel-server}"
BIN_DIR="${CES_BIN_DIR:-$HOME/.local/bin}"
DATA_HOME="${CES_DATA_HOME:-$HOME/ces-data}"
MODE="server"
staging=""
download=""

log() { printf '[ces 安装] %s\n' "$*" >&2; }
die() { printf '[ces 安装] 错误：%s\n' "$*" >&2; exit 1; }
cleanup() {
    [[ -n "$download" ]] && rm -rf -- "$download"
    [[ -n "$staging" ]] && rm -rf -- "$staging"
    return 0
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
compile-excel-server 一键安装（macOS / Linux）

  curl -fsSL https://raw.githubusercontent.com/qingshanfeihu/compile-excel-server/main/install.sh | bash
  curl -fsSL …/install.sh | bash -s -- --gateway     改装跳板机网关 cexg（只有 Linux x86_64）
  ./install.sh --from-source                         从当前代码目录安装（开发用）

环境变量：CES_VERSION（指定版本）、CES_PREFIX（程序放在哪里）、CES_BIN_DIR（命令放在哪里）、
CES_DATA_HOME（默认数据目录）、CES_REPO（从哪个仓库下载）
EOF
}

for arg in "$@"; do
    case "$arg" in
        --gateway|--from-source)
            [[ "$MODE" == "server" ]] || die "--gateway 和 --from-source 只能选一个"
            if [[ "$arg" == --gateway ]]; then MODE="gateway"; else MODE="source"; fi ;;
        -h|--help) usage; exit 0 ;;
        *) die "不认识的选项：$arg（可用 --gateway、--from-source、--help）" ;;
    esac
done

if [[ "$MODE" == "gateway" ]]; then
    NAME="cexg"
    PREFIX="${CES_PREFIX:-$HOME/.local/share/cexg}"
    SUPPORTED="linux-x86_64"
    LINKS=("cexg")
else
    NAME="compile-excel-server"
    PREFIX="${CES_PREFIX:-$HOME/.local/share/compile-excel-server}"
    SUPPORTED="darwin-arm64 darwin-x86_64 linux-x86_64"
    LINKS=("ces" "compile-excel-server")
fi

platform() {
    local os arch
    case "$(uname -s)" in
        Darwin) os="darwin" ;;
        Linux) os="linux" ;;
        *) die "不支持这个操作系统：$(uname -s)。Windows 请看 docs/development.md 里的源码安装。" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="arm64" ;;
        *) die "不支持这种 CPU：$(uname -m)" ;;
    esac
    printf '%s-%s' "$os" "$arch"
}

resolve_version() {
    if [[ -n "${CES_VERSION:-}" ]]; then printf '%s' "${CES_VERSION#v}"; return; fi
    local latest=""
    # 走网页跳转拿最新版本号：不占 GitHub API 的访问次数
    latest="$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
    if [[ "$latest" == */releases/tag/* ]]; then printf '%s' "${latest##*/v}"; return; fi
    if command -v gh >/dev/null 2>&1; then
        latest="$(gh api "repos/${REPO}/releases/latest" --jq .tag_name 2>/dev/null || true)"
        [[ -n "$latest" ]] && { printf '%s' "${latest#v}"; return; }
    fi
    die "查不到最新版本（网络不通？）。可以用 CES_VERSION=<版本号> 指定"
}

fetch() {  # $1=文件名 $2=版本 $3=保存到
    local url="https://github.com/${REPO}/releases/download/v$2/$1"
    if curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$3" 2>/dev/null; then return 0; fi
    if command -v gh >/dev/null 2>&1 && \
        gh release download "v$2" --repo "$REPO" --pattern "$1" --output "$3" --clobber \
            >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else die "缺少 sha256sum 或 shasum，无法核对安装包"; fi
}

switch_current() {  # 原子地把 current 链接换到 $1（相对路径）
    local tmp="$PREFIX/.current.$$"
    rm -f -- "$tmp"
    ln -s "$1" "$tmp"
    if mv -T "$tmp" "$PREFIX/current" 2>/dev/null; then return 0; fi      # GNU mv
    if mv -h "$tmp" "$PREFIX/current" 2>/dev/null; then return 0; fi      # macOS mv
    rm -f -- "$tmp"
    ln -sfn "$1" "$PREFIX/current"
}

smoke_test() {  # 新程序先在临时位置跑一次，能跑才换上去
    local exe="$1" rc=0
    if [[ "$MODE" == "gateway" ]]; then
        "$exe" sample-config >/dev/null 2>&1 || rc=$?
    else
        "$exe" version >/dev/null 2>&1 || rc=$?
        [[ "$rc" == 64 ]] && rc=0   # 0.2.0 及更早没有 version 子命令，打印用法后返回 64
    fi
    [[ "$rc" == 0 ]] || die "新版本试运行失败（返回码 $rc），原来的版本没有动"
}

add_to_path() {
    [[ ":$PATH:" == *":${BIN_DIR}:"* ]] && return 0
    local rc
    case "${SHELL:-}" in
        */zsh) rc="$HOME/.zshrc" ;;
        */bash) if [[ "$(uname -s)" == Darwin ]]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
        *) log "请把 ${BIN_DIR} 加进 PATH，然后重开终端"; return 0 ;;
    esac
    if ! grep -q '# ces path' "$rc" 2>/dev/null; then
        printf '\n# ces path\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$rc"
        log "已把 ${BIN_DIR} 加进 PATH（写在 ${rc}）"
    fi
    log "当前终端先运行：source ${rc}（或者重开一个终端）"
}

install_release() {
    command -v curl >/dev/null 2>&1 || die "缺少命令 curl"
    command -v tar >/dev/null 2>&1 || die "缺少命令 tar"
    local plat version asset expected actual exe
    plat="$(platform)"
    if [[ " $SUPPORTED " != *" $plat "* ]]; then
        if [[ "$MODE" == "gateway" ]]; then
            die "网关只有 Linux x86_64 的安装包，这台是 ${plat}"
        fi
        die "没有 ${plat} 的安装包。可以从源码安装：git clone https://github.com/${REPO}.git && cd compile-excel-server && ./install.sh --from-source（需要 python3）"
    fi
    version="$(resolve_version)"
    asset="${NAME}-${plat}.tar.gz"
    download="$(mktemp -d)"
    log "下载 ${asset}（版本 ${version}）"
    fetch "$asset" "$version" "$download/$asset" || die "下载失败：版本 ${version} 里没有 ${asset}，或者网络不通"
    fetch "SHA256SUMS" "$version" "$download/SHA256SUMS" || {
        [[ "${CES_SKIP_VERIFY:-}" == 1 ]] || die "版本 ${version} 没有 SHA256SUMS，无法核对安装包（确认来源可信后可设 CES_SKIP_VERIFY=1）"
        log "警告：按 CES_SKIP_VERIFY=1 跳过了核对"
    }
    if [[ -f "$download/SHA256SUMS" ]]; then
        expected="$(awk -v name="$asset" '$2 == name || $2 == "*"name { print $1 }' "$download/SHA256SUMS")"
        [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die "SHA256SUMS 里没有 ${asset}"
        actual="$(sha256_of "$download/$asset")"
        [[ "$actual" == "$expected" ]] || die "安装包的 SHA256 与 SHA256SUMS 不一致，可能下载不完整或被篡改"
        log "SHA256 核对通过"
    fi
    while IFS= read -r entry; do
        [[ "$entry" == "$NAME" || "$entry" == "$NAME/"* ]] || die "安装包里有意外的文件：$entry"
        [[ "$entry" != /* && "/$entry/" != */../* ]] || die "安装包里有不安全的路径：$entry"
    done < <(tar -tzf "$download/$asset")

    mkdir -p "$PREFIX/versions" "$BIN_DIR"
    staging="$(mktemp -d "$PREFIX/versions/.staging.XXXXXX")"
    chmod 755 "$staging"   # mktemp 建的是 700；服务账号与安装账号不同时要能进来
    tar --no-same-owner -xzf "$download/$asset" -C "$staging"
    exe="$staging/$NAME/$NAME"
    [[ -x "$exe" ]] || die "安装包里找不到可执行文件 ${NAME}"
    smoke_test "$exe"
    printf '%s\n' "$version" > "$staging/VERSION"

    local stamp target previous=""
    stamp="$(date +%Y%m%d%H%M%S)"
    target="${version}-${stamp}"
    mv "$staging" "$PREFIX/versions/$target"
    staging=""
    if [[ -L "$PREFIX/current" ]]; then
        previous="$(readlink "$PREFIX/current")"
        previous="${previous##*/}"
    elif [[ -d "$PREFIX/current" ]]; then
        # 旧版安装脚本的布局：current 本身是目录。挪进 versions/ 当作上一个版本
        previous="legacy-${stamp}"
        mv "$PREFIX/current" "$PREFIX/versions/$previous"
    fi
    switch_current "versions/$target"
    for dir in "$PREFIX"/versions/*; do
        local base="${dir##*/}"
        [[ "$base" == "$target" || "$base" == "$previous" ]] && continue
        rm -rf -- "$dir"
    done
    exe="$PREFIX/current/$NAME/$NAME"
    for link in "${LINKS[@]}"; do ln -sfn "$exe" "$BIN_DIR/$link"; done
    log "已安装 ${NAME} ${version}：${BIN_DIR}/${LINKS[0]}"
    [[ "${CES_UPDATE:-}" == 1 ]] || add_to_path
    next_steps "$version"
}

next_steps() {
    if [[ "${CES_UPDATE:-}" == 1 ]]; then
        log "已更新到 $1"
        return
    fi
    if [[ "$MODE" == "gateway" ]]; then
        log "接下来（详见 docs/gateway.md）："
        log "  1. mkdir -p ~/.config/cexg && cexg sample-config > ~/.config/cexg/gateway.toml，按注释填写"
        log "  2. cexg check --config ~/.config/cexg/gateway.toml"
        log "  3. cexg serve --config ~/.config/cexg/gateway.toml（开机自启见 docs/gateway.md）"
        log "已经在运行的网关要重启才会用上新版本：sudo systemctl restart cexg"
        return
    fi
    mkdir -p "$DATA_HOME"
    local config="${CES_CONFIG_ROOT:-$HOME/.config/compile-excel-server}/install.json"
    if [[ -f "$config" ]]; then
        log "检测到已有配置。正在运行的服务要重启才会用上新版本：ces restart"
    else
        log "接下来运行：ces setup（配置向导，只问两件事）"
    fi
}

install_from_source() {
    command -v python3 >/dev/null 2>&1 || die "缺少 python3（源码安装需要）"
    local root venv wrapper
    root="$(cd "$(dirname "$0")" && pwd)"
    [[ -f "$root/ces_main.py" ]] || die "请在代码目录里运行 ./install.sh --from-source"
    venv="$PREFIX/venv"
    log "源码安装：${root}（Python 虚拟环境 ${venv}）"
    python3 -m venv "$venv"
    "$venv/bin/python" -m pip install -q --upgrade pip
    "$venv/bin/python" -m pip install -q -r "$root/requirements.txt"
    mkdir -p "$BIN_DIR" "$DATA_HOME"
    wrapper="$PREFIX/ces-run"
    cat > "$wrapper" <<EOF
#!/usr/bin/env bash
exec "$venv/bin/python" "$root/ces_main.py" "\$@"
EOF
    chmod +x "$wrapper"
    ln -sfn "$wrapper" "$BIN_DIR/compile-excel-server"
    ln -sfn "$wrapper" "$BIN_DIR/ces"
    log "已安装：${BIN_DIR}/ces"
    add_to_path
    log "接下来运行：ces setup（配置向导，只问两件事）"
}

if [[ "$MODE" == "source" ]]; then
    install_from_source
else
    install_release
fi
