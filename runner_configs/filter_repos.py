import json
from pathlib import Path


JSON_PATH = Path("batch_state.json")
TXT_PATH = Path("runner_configs/repo_to_analyze.txt")


def main() -> None:
    # Читаем json и получаем множество ключей
    with JSON_PATH.open("r", encoding="utf-8") as f:
        json_data = json.load(f)

    json_keys = set(json_data.keys())

    # Читаем txt построчно
    with TXT_PATH.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    # Оставляем только те строки, которых нет в json
    filtered_lines = []
    for line in lines:
        repo = line.strip()
        if repo and repo not in json_keys:
            filtered_lines.append(repo)

    # Перезаписываем txt
    with TXT_PATH.open("w", encoding="utf-8") as f:
        for repo in filtered_lines:
            f.write(repo + "\n")

    print(f"Было строк в txt: {len(lines)}")
    print(f"Ключей в json: {len(json_keys)}")
    print(f"Осталось строк в txt: {len(filtered_lines)}")


if __name__ == "__main__":
    main()