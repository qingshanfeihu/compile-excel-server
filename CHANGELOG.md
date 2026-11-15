# 更新记录

## 未发布

- `probe_show` 不再因为设备分页停在 `--More--` 而等满 45 秒并截断输出：读取前在 enable 提示符下发 `no page` 关闭本次登录的分页（不进配置模式、不发 `exit`；原来的 `terminal length 0` 不是 ArrayOS 命令，设备一直拒绝）；`no page` 被拒时回复带 `note`，照常按 `--More--` 逐页翻读。设备画的分页提示行是“换行、空格、`--More--`、空格”，代理认这个形状并吃掉擦除提示行的退格序列；回复只含声明的字段，终端原始字节只留在代理内部，不出网关。

## 0.4.7

- `case_results` 给每个案都带 `sessions`，通过的案也带。框架日志只记发出的命令，设备拒绝一条配置命令（例如回“Failed to execute the command”）时只在会话里看得到；只读一条查询结果的断言照样通过，核验方要能从会话里看出这种通过不算数。

## 0.4.6

- `build_install` 的请求可带 `attempt`（1 到 1000）：同一份字节签发方只派发一次，同一构建装失败后再装一次就是带 attempt 的新请求；回执回显它。

## 0.4.5

- `build_install` 先放镜像：配了 `[upgrade] image_source`（构建库里镜像所在目录）时，runner 在升级用例之前把镜像放到床内文件服务器（`[upgrade] stage_host`/`stage_dir`，缺省 InfoTest 的 server231 与 /var/www/html），同 InfoTest 的调度：文件已在且非空就不动，否则在跳板机上从构建库下载，经框架自己的主机登录写成临时名再换名。床内文件服务器连不上构建库、InfoTest 的镜像库又没有被测构建时，升级用例原先只会下到 0 字节。

## 0.4.4

- 新工具 `build_install`：照 InfoTest 用框架自己的升级用例（`smoke_test/system/upgrade/99999999{0,1,2}.py`，带 `test_build`）给床上每台设备装构建；用例文件复制到 `<任务>/ist_install/` 再跑，请求协议、恢复和结果读取与 `case_submit` 相同。`cexg gc` 一并认领装构建的落位目录和报告。
- 床上装的构建以设备自述为准：`env_prepare` 不再要求设备等于配置的 `[hub] build`，只要求落在同一段 conf 凭据里，并回 `device_build`；客户端的 `device_build` 与设备自述比。同一租约随后的 runner 以设备自述的构建起（结果库构建表跟着它）。

## 0.4.3

- 去掉跨机器墙钟判据，改用持久派发序号与单调时钟租约；旧 `not_after` 仅作记录，不参与判定。
