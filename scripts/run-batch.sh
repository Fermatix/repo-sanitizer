#!/usr/bin/env bash
# run-batch.sh — запуск repo-sanitizer batch run на Linux-сервере
# без привязки к терминалу (systemd-run или nohup fallback)
#
# Использование:
#   ./scripts/run-batch.sh start [batch.yaml]
#   ./scripts/run-batch.sh status
#   ./scripts/run-batch.sh logs
#   ./scripts/run-batch.sh stop

set -euo pipefail

UNIT_NAME="repo-sanitizer-batch"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOGFILE="$PROJECT_DIR/batch.log"
PIDFILE="$PROJECT_DIR/.repo-sanitizer.pid"

# ---------------------------------------------------------------------------
# Загрузка salt из .env (если существует) или из окружения
# ---------------------------------------------------------------------------
load_env() {
    if [[ -f "$PROJECT_DIR/.env" ]]; then
        # Читаем только строки вида KEY=VALUE, игнорируем комментарии
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
            # Устанавливаем только если переменная ещё не задана
            if [[ -z "${!key+x}" ]]; then
                export "$key=$value"
            fi
        done < "$PROJECT_DIR/.env"
    fi

    if [[ -z "${REPO_SANITIZER_SALT:-}" ]]; then
        echo "ERROR: REPO_SANITIZER_SALT не задан." >&2
        echo "  Вариант 1: export REPO_SANITIZER_SALT=<секрет>" >&2
        echo "  Вариант 2: создай $PROJECT_DIR/.env с содержимым:" >&2
        echo "             REPO_SANITIZER_SALT=<секрет>" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Определяем метод запуска
# ---------------------------------------------------------------------------
has_systemd_run() {
    command -v systemd-run &>/dev/null && \
    systemctl --user is-system-running &>/dev/null 2>&1 || \
    systemd-run --user --test true &>/dev/null 2>&1
}

use_systemd=false
if command -v systemd-run &>/dev/null && systemd-run --user --test /bin/true &>/dev/null 2>&1; then
    use_systemd=true
fi

# ---------------------------------------------------------------------------
cmd="${1:-help}"
shift || true

case "$cmd" in

# ── start ──────────────────────────────────────────────────────────────────
start)
    CONFIG="${1:-batch.yaml}"
    # Разрешаем относительный путь от директории проекта
    if [[ ! "$CONFIG" = /* ]]; then
        CONFIG="$PROJECT_DIR/$CONFIG"
    fi

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: файл конфига не найден: $CONFIG" >&2
        exit 1
    fi

    load_env

    if $use_systemd; then
        # Проверяем: уже запущен?
        if systemctl --user is-active --quiet "$UNIT_NAME" 2>/dev/null; then
            echo "Уже запущен (systemd unit $UNIT_NAME)."
            echo "Используй: ./scripts/run-batch.sh status"
            exit 1
        fi

        systemd-run \
            --user \
            --no-block \
            --unit="$UNIT_NAME" \
            --working-directory="$PROJECT_DIR" \
            --setenv="REPO_SANITIZER_SALT=$REPO_SANITIZER_SALT" \
            uv run repo-sanitizer batch run --config "$CONFIG"

        echo ""
        echo "Запущено через systemd (unit: $UNIT_NAME)"
        echo ""
        echo "Мониторинг:"
        echo "  ./scripts/run-batch.sh logs     # live логи"
        echo "  ./scripts/run-batch.sh status   # статус"
        echo "  ./scripts/run-batch.sh stop     # остановить"

    else
        # Fallback: nohup + disown
        if [[ -f "$PIDFILE" ]]; then
            OLD_PID=$(cat "$PIDFILE")
            if kill -0 "$OLD_PID" 2>/dev/null; then
                echo "Уже запущен (PID $OLD_PID)."
                echo "Используй: ./scripts/run-batch.sh status"
                exit 1
            fi
        fi

        nohup env REPO_SANITIZER_SALT="$REPO_SANITIZER_SALT" \
            uv run repo-sanitizer batch run --config "$CONFIG" \
            >> "$LOGFILE" 2>&1 &
        echo $! > "$PIDFILE"
        disown

        echo ""
        echo "Запущено через nohup (PID $(cat "$PIDFILE"))"
        echo "Логи: $LOGFILE"
        echo ""
        echo "Мониторинг:"
        echo "  ./scripts/run-batch.sh logs     # live логи"
        echo "  ./scripts/run-batch.sh status   # статус"
        echo "  ./scripts/run-batch.sh stop     # остановить"
    fi
    ;;

# ── status ─────────────────────────────────────────────────────────────────
status)
    if $use_systemd; then
        systemctl --user status "$UNIT_NAME" --no-pager 2>/dev/null || \
            echo "Unit $UNIT_NAME не найден или уже завершён."
    else
        if [[ -f "$PIDFILE" ]]; then
            PID=$(cat "$PIDFILE")
            if kill -0 "$PID" 2>/dev/null; then
                echo "Запущен (PID $PID)"
                echo "Логи: $LOGFILE"
            else
                echo "Не запущен (PID $PID устарел)"
                rm -f "$PIDFILE"
            fi
        else
            echo "Не запущен (PID-файл не найден)"
        fi
    fi
    ;;

# ── logs ───────────────────────────────────────────────────────────────────
logs)
    if $use_systemd; then
        journalctl --user -u "$UNIT_NAME" -f --no-pager
    else
        if [[ -f "$LOGFILE" ]]; then
            tail -f "$LOGFILE"
        else
            echo "Лог-файл не найден: $LOGFILE" >&2
            exit 1
        fi
    fi
    ;;

# ── stop ───────────────────────────────────────────────────────────────────
stop)
    if $use_systemd; then
        if systemctl --user is-active --quiet "$UNIT_NAME" 2>/dev/null; then
            systemctl --user stop "$UNIT_NAME"
            echo "Остановлено."
        else
            echo "Unit $UNIT_NAME не запущен."
        fi
    else
        if [[ -f "$PIDFILE" ]]; then
            PID=$(cat "$PIDFILE")
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID"
                rm -f "$PIDFILE"
                echo "Остановлено (PID $PID)."
            else
                echo "Процесс уже завершён."
                rm -f "$PIDFILE"
            fi
        else
            echo "Не запущен (PID-файл не найден)."
        fi
    fi
    ;;

# ── help ───────────────────────────────────────────────────────────────────
*)
    echo "Использование:"
    echo "  ./scripts/run-batch.sh start [batch.yaml]   # запустить в фоне"
    echo "  ./scripts/run-batch.sh status               # статус / PID"
    echo "  ./scripts/run-batch.sh logs                 # live логи"
    echo "  ./scripts/run-batch.sh stop                 # остановить"
    echo ""
    echo "Salt передаётся через переменную окружения REPO_SANITIZER_SALT"
    echo "или через файл .env в корне проекта."
    ;;

esac
