#!/usr/bin/env bash
# compile-excel-server 一键安装：从 GitHub Releases 拉取 PyInstaller onedir 资产。
#
#   curl -fsSL https://raw.githubusercontent.com/qingshanfeihu/compile-excel-server/main/install.sh | bash
#
# 形态与 circle 相同：下载平台自包含二进制 → ~/.local/share → ~/.local/bin 软链，
# 不依赖本机 Python。仓库为私有仓时 curl 拿不到 raw/release——自动降级 gh（需 gh auth login）。
# 开发/无 Release 环境：./install.sh --from-source（隔离 venv 安装，同样不污染用户环境）。
#
# 环境变量:
#   CES_REPO        默认 qingshanfeihu/compile-excel-server
#   CES_VERSION     钉死版本（如 0.1.0 / v0.1.0）；未设取最新 Release
#   CES_BIN_DIR     默认 ~/.local/bin
#   CES_PREFIX      onedir 解压根，默认 ~/.local/share/compile-excel-server
#   CES_DATA_HOME   运行数据根，默认 ~/ces-data（安装器只创建空目录，配置走 ces setup）

set -euo pipefail

CES_REPO="${CES_REPO:-qingshanfeihu/compile-excel-server}"
GITHUB_API="https://api.github.com/repos/${CES_REPO}"
BIN_DIR="${CES_BIN_DIR:-$HOME/.local/bin}"
PREFIX="${CES_PREFIX:-$HOME/.local/share/compile-excel-server}"
DATA_HOME="${CES_DATA_HOME:-$HOME/ces-data}"
BIN_NAME="ces"

log()  { printf '[ces-install] %s\n' "$*" >&2; }
die()  { printf '[ces-install] 错误: %s\n' "$*" >&2; exit 1; }

detect_asset() {
    local os arch
    os="$(uname -s)"; arch="$(uname -m)"
    case "$os" in
        Darwin) os_tag="darwin" ;;
        Linux)  os_tag="linux" ;;
        *) die "暂不支持的 OS: $os（Windows 请用 --from-source + python3，见 README）" ;;
    esac
    case "$arch" in
        x86_64|amd64) arch_tag="x86_64" ;;
        arm64|aarch64) arch_tag="arm64" ;;
        *) die "暂不支持的 arch: $arch" ;;
    esac
    printf 'compile-excel-server-%s-%s.tar.gz' "$os_tag" "$arch_tag"
}

resolve_version() {
    if [[ -n "${CES_VERSION:-}" ]]; then printf '%s' "${CES_VERSION#v}"; return; fi
    command -v curl >/dev/null 2>&1 || die "缺少命令: curl"
    local tag=""
    tag="$(curl -fsSL "${GITHUB_API}/releases/latest" 2>/dev/null \
           | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)"
    if [[ -z "$tag" ]] && command -v gh >/dev/null 2>&1; then
        tag="$(gh api "repos/${CES_REPO}/releases/latest" --jq .tag_name 2>/dev/null || true)"
    fi
    [[ -n "$tag" ]] || die "无法解析最新 Release（${CES_REPO}）；私有仓需 gh auth login，或 CES_VERSION=<tag> 钉版本"
    printf '%s' "${tag#v}"
}

fetch_asset() {  # $1=url $2=输出
    if curl -fsSL "$1" -o "$2" 2>/dev/null; then return 0; fi
    if command -v gh >/dev/null 2>&1; then
        local tag="${CES_VERSION:-}"
        [[ -n "$tag" ]] || tag="v$(resolve_version)"
        gh release download "${tag#v}" --repo "${CES_REPO}" \
           --pattern "$(basename "$1")" --output "$2" >/dev/null 2>&1 && return 0
    fi
    return 1
}

install_binary() {
    command -v curl >/dev/null 2>&1 || die "缺少命令: curl"
    command -v tar >/dev/null 2>&1 || die "缺少命令: tar"
    local version asset url tmp
    version="$(resolve_version)"
    asset="$(detect_asset)"
    url="https://github.com/${CES_REPO}/releases/download/v${version}/${asset}"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    log "下载 $url"
    fetch_asset "$url" "$tmp/$asset" || die "下载失败（私有仓需 gh auth login 且账号有仓库权限）"
    mkdir -p "$PREFIX" "$BIN_DIR" "$DATA_HOME"
    rm -rf "$PREFIX/current"
    mkdir -p "$PREFIX/current"
    tar -xzf "$tmp/$asset" -C "$PREFIX/current"

    local exe
    if [[ -x "$PREFIX/current/compile-excel-server/compile-excel-server" ]]; then
        exe="$PREFIX/current/compile-excel-server/compile-excel-server"
    elif [[ -x "$PREFIX/current/compile-excel-server" ]]; then
        exe="$PREFIX/current/compile-excel-server"
    else
        die "Release 资产布局异常：未找到可执行文件 compile-excel-server"
    fi
    ln -sfn "$exe" "$BIN_DIR/compile-excel-server"
    ln -sfn "$exe" "$BIN_DIR/$BIN_NAME"
    log "已安装: ${BIN_DIR}/ces → ${exe}"
    log "数据根: ${DATA_HOME}（首次配置: ces setup）"

    if [[ ":$PATH:" == *":${BIN_DIR}:"* ]]; then
        log "安装完成。开始使用："
        log "  ces setup    # 配置向导（工件/手册/KMS 地址）"
        log "  ces          # 管理菜单"
    else
        local rc="$HOME/.zshrc"
        [[ "${SHELL:-}" == *bash* ]] && rc="$HOME/.bashrc"
        if ! grep -q '# ces path' "$rc" 2>/dev/null; then
            printf '\n# ces path\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$rc"
            log "已将 ${BIN_DIR} 写入 ${rc}"
        fi
        log "安装完成。当前终端生效：source ${rc} （或重开终端），然后: ces setup"
    fi
}

install_from_source() {
    command -v python3 >/dev/null 2>&1 || die "缺少命令: python3（--from-source 需要）"
    local root
    root="$(cd "$(dirname "$0")" && pwd)"
    local venv="$PREFIX/venv"
    log "源码安装（隔离 venv，不污染系统环境）: $root"
    python3 -m venv "$venv"
    "$venv/bin/python" -m pip install -q --upgrade pip
    "$venv/bin/python" -m pip install -q -r "$root/requirements.txt"
    mkdir -p "$BIN_DIR" "$DATA_HOME"
    local wrapper="$PREFIX/ces-run"
    cat > "$wrapper" <<EOF
#!/usr/bin/env bash
exec "$venv/bin/python" "$root/ces_main.py" "\$@"
EOF
    chmod +x "$wrapper"
    ln -sfn "$wrapper" "$BIN_DIR/compile-excel-server"
    ln -sfn "$wrapper" "$BIN_DIR/$BIN_NAME"
    log "已安装: ${BIN_DIR}/ces → ${wrapper}"
    log "数据根: ${DATA_HOME}（首次配置: ces setup）"
    log "安装完成。开始使用: ces setup / ces"
}

main() {
    if [[ "${1:-}" == "--from-source" ]]; then
        install_from_source
        return
    fi
    install_binary
}

main "$@"
