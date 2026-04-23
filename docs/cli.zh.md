# Smart Unpacker CLI 使用说明

Smart Unpacker 的命令行入口支持扫描、检查、解压、密码预览和配置管理。

常见启动方式：

```powershell
python smart-unpacker.py <command> [options] [paths...]
python -m smart_unpacker <command> [options] [paths...]
```

发布包中也可以直接使用可执行文件：

```powershell
SmartUnpacker <command> [options] [paths...]
```

## 通用参数

以下参数适用于大多数子命令：

- `--json`：以 JSON 格式输出结果，适合脚本读取。
- `--quiet`：减少终端输出。
- `--verbose`：输出更详细的原因、密码摘要或扫描细节。
- `--pause-on-exit`：命令结束后等待按键退出，适合右键菜单场景。
- `--no-pause`：命令结束后不暂停。

注意：`config` 子命令的通用参数建议放在 `config` 后、具体动作前，例如：

```powershell
python smart-unpacker.py config --json show
```

## 执行类命令的临时配置覆盖

`extract`、`scan` 和 `inspect` 支持通过参数临时覆盖部分配置。临时覆盖只影响本次运行，不会写入 `smart_unpacker_config.json`。

可覆盖参数：

- `--min-inspection-size-bytes <N>`：覆盖 `extraction_rules.min_inspection_size_bytes`，`N` 必须是非负整数。
- `--recursive-extract <VALUE>`：覆盖 `recursive_extract`，取值为正整数、`"*"` 或 `"?"`。
- `--scheduler-profile <auto|conservative|aggressive>`：覆盖 `performance.scheduler_profile`。
- `--archive-cleanup-mode <keep|recycle|delete>`：覆盖 `post_extract.archive_cleanup_mode`。
- `--flatten-single-directory`：本次运行启用单子目录压平。
- `--no-flatten-single-directory`：本次运行禁用单子目录压平。

实际影响：

- `--min-inspection-size-bytes` 会影响 `extract`、`scan`、`inspect` 的识别结果。
- `--recursive-extract` 主要影响 `extract`，对 `scan` 和 `inspect` 基本没有实际意义。
- `--scheduler-profile` 主要影响 `extract` 的并发调度。
- `--archive-cleanup-mode` 和压平参数只在 `extract` 的后处理阶段生效。

示例：

```powershell
python smart-unpacker.py scan .\archives --min-inspection-size-bytes 0
python smart-unpacker.py inspect .\archives --min-inspection-size-bytes 0 --verbose
python smart-unpacker.py extract .\archives --recursive-extract 1 --archive-cleanup-mode keep --no-flatten-single-directory
python smart-unpacker.py extract .\archives --scheduler-profile aggressive
```

## `inspect`

用途：递归检查文件或目录，输出每个文件的识别结果、命中原因和是否建议解压。

命令格式：

```powershell
python smart-unpacker.py inspect [options] <paths...>
```

常用示例：

```powershell
python smart-unpacker.py inspect .\fixtures
python smart-unpacker.py inspect .\archives --verbose
python smart-unpacker.py inspect .\archives --json
python smart-unpacker.py inspect .\archives --min-inspection-size-bytes 0
```

执行效果：

- 不解压文件。
- 不移动、不删除原文件。
- 不执行预重命名。
- 会输出每个文件的 `archive`、`maybe_archive`、`not_archive` 判定。
- `--verbose` 会显示更多评分原因。

## `scan`

用途：按任务维度汇总可处理归档，适合在真正解压前查看会生成哪些解压任务。

命令格式：

```powershell
python smart-unpacker.py scan [options] <paths...>
```

常用示例：

```powershell
python smart-unpacker.py scan .\archives
python smart-unpacker.py scan .\archives --verbose
python smart-unpacker.py scan .\archives --json
python smart-unpacker.py scan .\archives --min-inspection-size-bytes 0
```

执行效果：

- 不解压文件。
- 不移动、不删除原文件。
- 不执行预重命名。
- 会应用后缀规则、黑名单目录、黑名单文件名、场景规则和评分阈值。
- 输出的是“解压任务”，不是逐文件检查结果。

## `extract`

用途：执行完整流程，包括预检查、扫描、密码尝试、解压、递归处理和后处理。

命令格式：

```powershell
python smart-unpacker.py extract [options] <paths...>
```

常用示例：

```powershell
python smart-unpacker.py extract .\archives
python smart-unpacker.py extract .\archives -p "secret"
python smart-unpacker.py extract .\archives --password-file .\passwords.txt
python smart-unpacker.py extract .\archives --prompt-passwords
python smart-unpacker.py extract .\archives --recursive-extract 1
python smart-unpacker.py extract .\archives --archive-cleanup-mode keep
python smart-unpacker.py extract .\archives --archive-cleanup-mode delete
python smart-unpacker.py extract .\archives --no-flatten-single-directory
```

执行效果：

- 会执行预重命名，修复部分伪装压缩包后缀和分卷后缀。
- 会扫描归档任务并调用 7-Zip 解压。
- 成功解压后会根据 `archive_cleanup_mode` 处理原归档。
- 成功解压后会根据 `flatten_single_directory` 决定是否压平单子目录。
- 递归行为由 `recursive_extract` 或 `--recursive-extract` 控制。

退出码：

- `0`：命令成功，且没有失败任务。
- `1`：命令运行完成，但存在解压失败任务。
- `2`：参数错误、目标不存在或配置命令输入非法。
- `3`：运行时异常。

## 密码参数

以下参数适用于 `extract` 和 `passwords`：

- `-p, --password <PASSWORD>`：指定一个密码，可重复传入多次。
- `--password-file <PATH>`：从文件读取密码，每行一个。
- `--prompt-passwords`：通过终端交互输入密码列表。
- `--no-builtin-passwords`：禁用内置高频密码。

密码合并顺序：

```text
命令行/密码文件/交互输入密码 -> 最近成功密码 -> 内置高频密码
```

重复密码会去重，并保留较靠前来源的顺序。

示例：

```powershell
python smart-unpacker.py extract .\archives -p 123 -p 456
python smart-unpacker.py extract .\archives --password-file .\passwords.txt
python smart-unpacker.py extract .\archives --prompt-passwords --no-builtin-passwords
```

## `passwords`

用途：查看当前最终会参与尝试的密码列表。

命令格式：

```powershell
python smart-unpacker.py passwords [options]
```

常用示例：

```powershell
python smart-unpacker.py passwords
python smart-unpacker.py passwords -p 123 -p 456
python smart-unpacker.py passwords --password-file .\passwords.txt --json
python smart-unpacker.py passwords --no-builtin-passwords
```

执行效果：

- 不扫描文件。
- 不解压文件。
- 不修改配置。
- 只显示密码来源和最终尝试顺序。

## `config`

用途：查看或修改 `smart_unpacker_config.json` 中的常用配置。

`config` 修改的是配置文件本身，和执行类命令的临时覆盖不同。修改后会影响之后的运行。

### `config show`

显示当前配置文件内容。

```powershell
python smart-unpacker.py config show
python smart-unpacker.py config --json show
```

执行效果：

- 如果配置文件不存在，会读取默认配置结构作为显示内容。
- `--json` 模式下，配置内容会出现在结果的 `items[0]` 中。

### `config set`

修改一个常用配置项。

命令格式：

```powershell
python smart-unpacker.py config set <key> <value>
```

支持的 `key`：

- `min_inspection_size_bytes`
- `recursive_extract`
- `scheduler_profile`
- `archive_cleanup_mode`
- `flatten_single_directory`

示例：

```powershell
python smart-unpacker.py config set min_inspection_size_bytes 0
python smart-unpacker.py config set recursive_extract 1
python smart-unpacker.py config set recursive_extract "*"
python smart-unpacker.py config set recursive_extract "?"
python smart-unpacker.py config set scheduler_profile conservative
python smart-unpacker.py config set scheduler_profile aggressive
python smart-unpacker.py config set archive_cleanup_mode keep
python smart-unpacker.py config set archive_cleanup_mode recycle
python smart-unpacker.py config set archive_cleanup_mode delete
python smart-unpacker.py config set flatten_single_directory false
python smart-unpacker.py config set flatten_single_directory true
```

字段写入位置：

- `min_inspection_size_bytes` 写入 `extraction_rules.min_inspection_size_bytes`。
- `recursive_extract` 写入顶层 `recursive_extract`。
- `scheduler_profile` 写入 `performance.scheduler_profile`。
- `archive_cleanup_mode` 写入 `post_extract.archive_cleanup_mode`。
- `flatten_single_directory` 写入 `post_extract.flatten_single_directory`。

取值规则：

- `min_inspection_size_bytes` 必须是非负整数。
- `recursive_extract` 必须是正整数、`"*"` 或 `"?"`。
- `scheduler_profile` 必须是 `auto`、`conservative` 或 `aggressive`。
- `archive_cleanup_mode` 必须是 `keep`、`recycle` 或 `delete`。
- `flatten_single_directory` 支持 `true/false`、`yes/no`、`1/0`。

### `config blacklist list`

查看目录黑名单和文件名黑名单。

```powershell
python smart-unpacker.py config blacklist list
python smart-unpacker.py config --json blacklist list
```

### `config blacklist add-dir`

添加目录黑名单正则。

```powershell
python smart-unpacker.py config blacklist add-dir "FBX/weapon"
python smart-unpacker.py config blacklist add-dir ".*/weapon"
python smart-unpacker.py config blacklist add-dir "^cache$"
```

执行效果：

- 写入 `extraction_rules.blacklist.directory_patterns`。
- 新增规则会先按 Python 正则校验。
- 已存在的相同字符串不会重复添加。
- 推荐使用正斜杠 `/` 表示目录层级，避免 JSON 反斜杠转义。

### `config blacklist remove-dir`

删除目录黑名单正则。

```powershell
python smart-unpacker.py config blacklist remove-dir "FBX/weapon"
```

执行效果：

- 从 `extraction_rules.blacklist.directory_patterns` 删除完全相同的字符串。
- 删除时不要求该字符串是合法正则，方便移除历史错误配置。

### `config blacklist add-file`

添加文件名黑名单正则。

```powershell
python smart-unpacker.py config blacklist add-file "^readme\\.zip$"
python smart-unpacker.py config blacklist add-file ".*\\.unitypackage$"
python smart-unpacker.py config blacklist add-file "FBX/weapon/demo\\.zip"
```

执行效果：

- 写入 `extraction_rules.blacklist.filename_patterns`。
- 新增规则会先按 Python 正则校验。
- 会同时匹配完整文件名和相对文件路径。

### `config blacklist remove-file`

删除文件名黑名单正则。

```powershell
python smart-unpacker.py config blacklist remove-file "FBX/weapon/demo\\.zip"
```

执行效果：

- 从 `extraction_rules.blacklist.filename_patterns` 删除完全相同的字符串。
- 删除时不要求该字符串是合法正则。

## `--json` 输出结构

所有命令的 JSON 输出都使用相同外层结构：

```json
{
  "command": "scan",
  "inputs": {},
  "summary": {},
  "errors": [],
  "items": [],
  "tasks": [],
  "logs": []
}
```

字段含义：

- `command`：执行的子命令。
- `inputs`：命令输入摘要，包括路径、覆盖参数等。
- `summary`：汇总信息。
- `errors`：错误列表。
- `items`：逐项结果，例如 inspect 文件结果、密码摘要或配置内容。
- `tasks`：扫描到的解压任务，主要由 `scan` 使用。
- `logs`：运行日志。

## 推荐工作流

先查看配置：

```powershell
python smart-unpacker.py config show
```

对复杂目录先扫描：

```powershell
python smart-unpacker.py scan .\archives --verbose
```

如果怀疑小文件被跳过，临时降低阈值：

```powershell
python smart-unpacker.py scan .\archives --min-inspection-size-bytes 0
```

如果确认某个目录不应处理，加入黑名单：

```powershell
python smart-unpacker.py config blacklist add-dir "FBX/weapon"
```

确认扫描结果符合预期后再解压：

```powershell
python smart-unpacker.py extract .\archives --prompt-passwords
```

如果只是临时试运行，不想移动原压缩包：

```powershell
python smart-unpacker.py extract .\archives --archive-cleanup-mode keep
```
