### 说明

AC的所有操作均在版本`AC13.0.15.097 Build20210304`上进行测试,不保证其它版本兼容性

### 安装与使用

安装

```bash
go get -u github.com/lyonspdy/sangfor
```

使用

```go
package main

import (
	"fmt"
	"github.com/lyonspdy/sangfor"
)

func main() {
	// secret字段需要在深信服AC上的"开放接口"打开并放通调用方IP后生成
	acSrv := sangfor.NewAC("192.168.1.1:9999", "YR9nQngmvhX&9BE83K")
	version, err := acSrv.GetVersion()
	if err != nil {
		errHandle...
	}
	doSomething ...
}
```

### 功能说明

当前只实现了深信服AC的相关API对接,由于API文档中存在太多问题, 导致部分接口无法正常适用,具体请参考说明中的`加粗部分`,以及代码注释中的 `TODO` 与 `FIXME`部分

未加粗及标记绿色块为测试ok。

状态接口:

- `GetVersion`- 获取版本信息  :green_book:
- `GetOnlineUserCount` - 获取在线用户数  :green_book:
- `GetSessionNum` - 获取当前设备会话数  :green_book:
- `GetInsideLib` - 获取设备内置库版本信息 :green_book:
- `GetLogNum` - 获取日志计数统计(拦截日志,记录日志)  :green_book:
- `GetCpuUsage` - 获取CPU使用率 :green_book:
- `GetMemUsage` - 获取内存使用率 :green_book:
- `GetDiskUsage` - 获取磁盘使用率 :green_book:
- `GetSysTime` - 获取设备的当前系统时间​ :green_book:
- `GetThroughput` - 获取设备当前上行和下行流量   :green_book:
- `GetUserRank` - 获取用户流量排行 (测试只返回前七位数据)  :green_book:
- `GetAppRank` - 获取应用流量排行  :green_book:
- `GetBandwidthUsage` - 获取带宽利用率 :green_book:

用户接口:

- `UserAdd` - 增加新用户  :green_book:
- `UserDel` - 删除用户  :green_book:
- `UserSearch` - 搜索用户
- `UserMod`  -修改用户信息 :green_book:
- `UserGet` - 获取一个用户   :green_book:
- `UserPolicySet` - 设置用户的上网策略（支持增删改） :green_book:
- `UserNetPolicyGet` - 获取用户关联的上网策略列表 **参数有误,需联系厂商确认**
- `UserFluxPolicySet` - 设置用户流控策略  **无法得知相关策略设置参数有误**
- `UserFluxPolicyGet` - 获取用户关联的流控策略列表 **参数有误,需联系厂商确认**
- `UserVerifyPassword` - 校验本地用户密码 **测试失败,实际调用的是获取用户详细信息接口**

在线用户接口:

- `OnlineUserGet` - 获取在线用户列表 （返回100条）  :green_book:
- `OnlineUserKick` - 强制注销在线用户   :green_book:
- `OnlineUserUp` - 上线在线用户(单点登录)  **参数有误,需联系厂商确认**

组接口:

- `GroupAdd` - 添加组  :green_book:
- `GroupDelete` - 删除组   :green_book:
- `GroupPut` - 修改组信息(只能修改组描述信息)  :green_book:
- `GroupNetPolicySet` - 指定/修改/删除组关联的上网策略（操作成功返回文字内容都为修改）  :green_book:
- `GroupNetPolicyGet` - 获取对应组关联的上网策略 **参数有误,需联系厂商确认**

策略接口:

- `PolicyNetGet` - 获取设备已有上网策略信息   :green_book:
- `PolicyFluxGet` - 获取设备已有流控策略信息  :green_book:

绑定相关接口:

- `BindUserSearch` - 查询用户和IP/MAC的绑定关系 **参数有误,需联系厂商确认**
- `BindUserAdd` - 增加用户的IP/MAC绑定 **参数有误,需联系厂商确认**
- `BindUserDel` - 删除用户和IP/MAC的绑定关系 **参数或操作步骤有误,需联系厂商确认**
- `BindIpmacSearch` - 查询IPMac绑定关系   :green_book:
- `BindIpmacAdd` - 增加IP/MAC绑定信息   :green_book:
- `BindIpmacDel` - 删除IP/MAC绑定信息   :green_book:

