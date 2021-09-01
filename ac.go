/**
 * @Author: daipengyuan
 * @Description: sangfor ac handler
 * @File:  ac
 * @Version: 1.0.0
 * @Date: 2021/5/25 09:58
 */

package sangfor

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const (
	acGet  = "GET"
	acPost = "POST"
	acPut  = "PUT"

	/* 错误信息 */
	acErrNoData   = `No data in body `
	acErrArgCheck = `Arguments check failed `

	/* Status接口 */
	acStatusVersion        = `status/version`         // 版本
	acStatusOnlineUser     = `status/online-user`     // 在线用户数
	acStatusSessionNum     = `status/session-num`     // 会话数
	acStatusInsideLib      = `status/insidelib`       // 内置库版本信息
	acStatusLogNum         = `status/log`             // 日志计数统计(拦截日志,记录日志)
	acStatusCpuUsage       = `status/cpu-usage`       // CPU利用率
	acStatusMemUsage       = `status/mem-usage`       // 内存利用率
	acStatusDiskUsage      = `status/disk-usage`      // 磁盘利用率
	acStatusSysTime        = `status/sys-time`        // 系统时间
	acStatusThroughput     = `status/throughput`      // 吞吐量(当前流量)
	acStatusUserRank       = `status/user-rank`       // 用户流量排行
	acStatusAppRank        = `status/app-rank`        // 应用流量排行
	acStatusBandwidthUsage = `status/bandwidth-usage` // 带宽利用率(百分比)

	/* 用户接口(BBC中心端也支持) */
	acUser           = `user`             // 用户(POST=添加,GET=按名称查找详细信息,verify=验证账号密码)
	acUserMod        = `user?method=PUT` // 用户(修改)
	acUserNetPolicy  = `user/netpolicy`   // 用户上网策略的增删改查
	acUserFluxPolicy = `user/fluxpolicy`  // 用户流控策略的增删改查

	/* 组接口(BBC中心端也支持) */
	acGroup          = `group`           // 添加组
	acGroupNetPolicy = `group/netpolicy` // 组上网策略操作

	/* 策略接口(BBC中心端也支持) */
	acNetPolicy  = `policy/netpolicy`  // 上网策略
	acFluxPolicy = `policy/fluxpolicy` // 流控策略

	/* BindInfo接口 */
	acBindInfoUser    = `bindinfo/user-bindinfo`  // 用户和IP/MAC的绑定关系(增加,查询)
	acBindInfoIpMac   = `ipmac-bindinfo`          // IPMAC绑定关系(查询)
	acBindInfoIpMacOp = `bindinfo/ipmac-bindinfo` // IPMAC绑定关系(增，删)
	/* OnlineUsers接口 */
	acOnlineUsers = `online-users` // 在线用户(上线(单点登录))
)

// NewAC 创建深信服AC操作对象,target为ip+端口,secret为AC上配置的密钥
// e.g: target=192.168.1.1:9999(默认端口为9999), secret=YR9nQngmvhX&9BE83K
func NewAC(target, secret string) *AC {
	ac := &AC{secret: secret, baseUrl: fmt.Sprintf("http://%s/v1/", target), ErrLangCN: true}
	return ac
}

type AC struct {
	baseUrl   string
	secret    string
	ErrLangCN bool // 是否设置返回错误信息为中文
}

// GetVersion 获取版本信息
func (ac *AC) GetVersion() (string, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusVersion, method: acGet})
	if err != nil {
		return "", err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// GetOnlineUserCount 获取在线用户计数
func (ac *AC) GetOnlineUserCount() (int, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusOnlineUser, method: acGet})
	if err != nil {
		return 0, err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return 0, err
	}
	if resp.Code != 0 {
		return 0, errors.New(resp.Message)
	}
	return int(resp.Data.(float64)), nil
}

// GetSessionNum 获取当前设备的会话数
func (ac *AC) GetSessionNum() (int, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusSessionNum, method: acGet})
	if err != nil {
		return 0, err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return 0, err
	}
	if resp.Code != 0 {
		return 0, errors.New(resp.Message)
	}
	return int(resp.Data.(float64)), nil
}

// InsideLib 内置库结构体(病毒库,URL库等)
type InsideLib struct {
	Name      string `json:"name"`       // 库名称
	Type      string `json:"type"`       // 库类型(kav=病毒库,url=URL库,up=网关补丁,contchk=应用识别,trace=审计规则库)
	Current   string `json:"current"`    // 当前版本
	New       string `json:"new"`        // 最新版本
	Expire    string `json:"expire"`     // 升级服务序列号过期时间
	Enable    bool   `json:"enable"`     // 是否启用自动升级
	IsExpired int    `json:"is_expired"` // 规则库是否过期(0=未过期,1=过期)
}

// GetInsideLib 获取设备内置库版本信息,包含病毒库,URL库等模块
func (ac *AC) GetInsideLib() ([]InsideLib, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusInsideLib, method: acGet})
	if err != nil {
		return nil, err
	}
	var r []InsideLib
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// LogNum 日志计数结构体
type LogNum struct {
	Block  int `json:"block"`  // 拦截日志计数
	Record int `json:"record"` // 记录日志计数
}

// GetLogNum 获取日志计数统计(拦截日志,记录日志)
func (ac *AC) GetLogNum() (*LogNum, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusLogNum, method: acGet})
	if err != nil {
		return nil, err
	}
	var r LogNum
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return &r, nil
}

// GetCpuUsage 获取设备的实时CPU使用率(百分比整数)
func (ac *AC) GetCpuUsage() (int, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusCpuUsage, method: acGet})
	if err != nil {
		return 0, err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return 0, err
	}
	if resp.Code != 0 {
		return 0, errors.New(resp.Message)
	}
	return int(resp.Data.(float64)), nil
}

// GetMemUsage 获取设备的实时内存使用率(百分比整数)
func (ac *AC) GetMemUsage() (int, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusMemUsage, method: acGet})
	if err != nil {
		return 0, err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return 0, err
	}
	if resp.Code != 0 {
		return 0, errors.New(resp.Message)
	}
	return int(resp.Data.(float64)), nil
}

// GetDiskUsage 获取设备的磁盘使用率(百分比整数)
func (ac *AC) GetDiskUsage() (int, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusDiskUsage, method: acGet})
	if err != nil {
		return 0, err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return 0, err
	}
	if resp.Code != 0 {
		return 0, errors.New(resp.Message)
	}
	return int(resp.Data.(float64)), nil
}

// GetSysTime 获取设备的当前系统时间(e.g:2017-12-13 17:52:11)
func (ac *AC) GetSysTime() (string, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusSysTime, method: acGet})
	if err != nil {
		return "", err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// ThroughputFilter 上下行流速过滤参数
type ThroughputFilter struct {
	Unit      string `json:"unit,omitempty"`      // 流量单位(取值bits/bytes)
	Interface string `json:"interface,omitempty"` // 接口名称
}

// Throughput 设备的上行和下行流速返回结构体
type Throughput struct {
	Recv int    `json:"recv"` // 接收流量
	Send int    `json:"send"` // 发出流量
	Unit string `json:"unit"` // 流量单位(bits或bytes)
}

// GetThroughput 获取设备当前上行和下行流量,bitUnit为true时使用bit单位,ifName匹配接口名称,默认统计所有WAN扣
func (ac *AC) GetThroughput(filter ...ThroughputFilter) (*Throughput, error) {
	var (
		req = &acReq{
			uri:    ac.baseUrl + acStatusThroughput,
			method: acPost,
			Query:  map[string]string{"_method": "GET"},
		}
	)
	if filter != nil {
		req.Data = map[string]interface{}{"filter": filter[0]}
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r Throughput
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return &r, nil
}

// UserRankFilter 用户流量排行过滤参数
// 过滤字段"groups","users","ips",同时只能选择其中一种过滤条件来过滤,
// 若同时传入多个过滤条件,则过滤条件只会生效1种,优先级为"groups > users > ips"
type UserRankFilter struct {
	Top    int      `json:"top,omitempty"`    // TopN排行
	Line   string   `json:"line,omitempty"`   // 线路号(0:所有线路，1-N:具体线路)
	Groups []string `json:"groups,omitempty"` // 要过滤的组(以"/"开头)
	Users  []string `json:"users,omitempty"`  // 要过滤的用户
	Ips    []string `json:"ips,omitempty"`    // 要过滤的IP(只支持单个IP,不支持IP组)
}

// UserRank 用户流量排行数据
type UserRank struct {
	Id      int    `json:"id"`      // 序号
	Name    string `json:"name"`    // 用户名
	Group   string `json:"group"`   // 组
	Ip      string `json:"ip"`      // IP
	Up      int    `json:"up"`      // 上行流量(bytes)
	Down    int    `json:"down"`    // 下行流量(bytes)
	Total   int    `json:"total"`   // 总流量(bytes)
	Session int    `json:"session"` // 会话数
	Status  bool   `json:"status"`  // 冻结状态(false为冻结)
	Detail  *struct {
		Data []struct {
			Id      int    `json:"id"`
			App     string `json:"app"` // 应用名称
			Up      int    `json:"up"`
			Down    int    `json:"down"`
			Total   int    `json:"total"`
			Percent int    `json:"percent"`
		} `json:"data,omitempty"`
	} `json:"detail,omitempty"` // 详细信息
}

// GetUserRank 获取用户流量排行
func (ac *AC) GetUserRank(filter ...UserRankFilter) ([]UserRank, error) {
	var (
		req = &acReq{
			uri:    ac.baseUrl + acStatusUserRank,
			method: acPost,
			Query:  map[string]string{"_method": "GET"},
		}
	)
	if filter != nil {
		req.Data = map[string]interface{}{"filter": filter[0]}
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r []UserRank
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// AppRankFilter 应用流量排行过滤参数
type AppRankFilter struct {
	Top    int      `json:"top,omitempty"`    // TopN排行
	Line   string   `json:"line,omitempty"`   // 线路号(0:所有线路，1-N:具体线路)
	Groups []string `json:"groups,omitempty"` // 要过滤的组(以"/"开头)
}

// AppRank 应用流量排行数据
type AppRank struct {
	App      string `json:"app"`
	Line     int    `json:"line"`
	LineName string `json:"line_name"`
	Up       int    `json:"up"`
	Down     int    `json:"down"`
	Total    int    `json:"total"`
	Rate     int    `json:"rate"`
	Session  int    `json:"session"`
	UserData *struct {
		Data []struct {
			User  string `json:"user"`
			Grp   string `json:"grp"`
			Ip    string `json:"ip"`
			Up    int    `json:"up"`
			Down  int    `json:"down"`
			Total int    `json:"total"`
		} `json:"data"`
		Count int `json:"count"`
	} `json:"user_data"`
}

// GetAppRank 获取应用流量排行
func (ac *AC) GetAppRank(filter ...AppRankFilter) ([]AppRank, error) {
	var (
		req = &acReq{
			uri:    ac.baseUrl + acStatusAppRank,
			method: acPost,
			Query:  map[string]string{"_method": "GET"}}
	)
	if filter != nil {
		req.Data = map[string]interface{}{"filter": filter[0]}
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r []AppRank
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// GetBandwidthUsage 获取带宽使用率
func (ac *AC) GetBandwidthUsage() (int, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acStatusBandwidthUsage, method: acGet})
	if err != nil {
		return 0, err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return 0, err
	}
	if resp.Code != 0 {
		return 0, errors.New(resp.Message)
	}
	return int(resp.Data.(float64)), nil
}

// UserAdd 增加用户传入结构体
type UserAdd struct {
	Name       string `json:"name"`                  // 用户名
	FatherPath string `json:"father_path,omitempty"` // 父组,即用户添加后所在组(以"/"开头,且不支持向域用户组添 加用户)
	Desc       string `json:"desc,omitempty"`        // 用户描述
	ShowName   string `json:"show_name,omitempty"`   // 用户显示名
	ExpireTime string `json:"expire_time,omitempty"` // 账号过期时间,格式为“YY-MM-dd hh:mm:ss”,为空或无此字段表示不过期
	// 扩展信息
	Enable     bool     `json:"enable,omitempty"`      // 是否启用该用户(true为启用)
	Logout     bool     `json:"logout,omitempty"`      // 密码认证成功后是否弹出注销窗口
	LimitIpmac []string `json:"limit_ipmac,omitempty"` // 限制登录地址(IP或MAC,IP支持单个或IP段 (192.168.1.1-192.168.1.2),MAC格式ee-ee-ee-ee-ee- ee)
	SelfPass   struct { // 本地密码(self_pass字段不为空时,表示要设置用户本地 密码,此时password字段不能为空)
		Enable     bool   `json:"enable,omitempty"`
		Password   string `json:"password,omitempty"`    // 本地密码
		ModifyOnce bool   `json:"modify_once,omitempty"` // 初次认证是否修改密码
	} `json:"self_pass,omitempty"`
	BindCfg []struct { // 用户绑定,可同时添加多条,支持IP、MAC、out_time: 绑定有效期(不需要时可去掉此条)
		Ip       string `json:"ip,omitempty"`       // e.g:192.168.1.2
		Mac      string `json:"mac,omitempty"`      // e.g:ac-ed-ee-ee-ee-ee
		OutTime  string `json:"out_time,omitempty"` // 过期时间(e.g:2019-10-31)
		Bindgoal string `json:"bindgoal,omitempty"` // 绑定方式(noauth:免认证,loginlimit:限制登录,noauth_and_loginlimit:免认证且限制登录)
		Desc     string `json:"desc,omitempty"`     // 绑定描述
	} `json:"bind_cfg,omitempty"`
	CommonUser *struct {
		AllowChange bool `json:"allow_change,omitempty"` // 是否允许修改本地密码
		Enable      bool `json:"enable,omitempty"`       // 是否允许多人使用该账号登录
	} `json:"common_user,omitempty"`
	CustomCfg map[string]string `json:"custom_cfg,omitempty"` // 自定义属性的键值对(e.g:{"attr1": "value1","attr2": "value2"})
}

// UserAdd 添加新用户
func (ac *AC) UserAdd(data UserAdd) (string, error) {
	var (
		req      = &acReq{uri: ac.baseUrl + acUser, method: acPost}
		postData = make(map[string]interface{})
	)
	if data.Name == "" {
		return "", errors.New("cannot add user without username")
	}
	jb, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(jb, &postData)
	if err != nil {
		return "", err
	}
	req.Data = postData
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// UserDel 删除用户
// TODO: 尚未单元测试 测试ok
func (ac *AC) UserDel(username string) (string, error) {
	var (
		req = &acReq{
			uri:    ac.baseUrl + acUser,
			method: acPost,
			Query:  map[string]string{"_method": "DELETE"},
			Data:   map[string]interface{}{"name": username},
		}
	)
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// TODO: 用户修改接口尚未实现,因为根据API接口文档描述无法得出具体行为,需要进一步测试 UserMod test ok

// UserDetail 用户详细信息(搜索或查找返回结构体)
type UserDetail struct {
	Name       string `json:"name"`        // 用户名
	ShowName   string `json:"show_name"`   // 显示名
	Desc       string `json:"desc"`        // 用户描述
	FatherPath string `json:"father_path"` // 用户所在组
	Create     string `json:"create"`      // 创建者
	CreateFlag bool   `json:"create_flag"` // 用户是否由认证或者自动同步添加的
	Enable     bool   `json:"enable"`      // 是否启用
	Logout     bool   `json:"logout"`      // 密码认证成功后是否弹出注销窗口
	//BindCfg    []string          `json:"bind_cfg,omitempty"`   // 用户IP,MAC绑定信息
	BindCfg   []map[string]string `json:"bind_cfg,omitempty"`   // 用户IP,MAC绑定信息
	CustomCfg map[string]string   `json:"custom_cfg,omitempty"` // 用户自定义属性键值对
	Policy    []NetPolicyInfo     `json:"policy,omitempty"`     // 用户关联的策略(具体到单条策略)
	SelfPass  struct {
		Enable     bool `json:"enable"`      // 用户是否启用密码
		ModifyOnce bool `json:"modify_once"` // 初次认证是否修改秘密
	} `json:"self_pass,omitempty"`
	LimitIpmac struct {
		Enable bool     `json:"enable"` // 是否开启登录限制
		Ipmac  []string `json:"ipmac"`  // 具体的IP,MAC登录限制列表
	}
	CommonUser struct {
		Enable      bool `json:"enable"`       // 是否允许多人同时使用该账号登录
		AllowChange bool `json:"allow_change"` // 是否允许修改本地密码
	} `json:"common_user"`
	ExpireTime struct {
		Enable bool   `json:"enable"`         // 是否启用账号过期
		Date   string `json:"date,omitempty"` // 过期日期(YYYY-MM-DD)
	} `json:"expire_time"`
}

// UserSearch 用户搜索传入结构体(最多返回100个)
type UserSearch struct {
	SearchType string `json:"search_type"` // 搜索类型(user/ip/mac)
	// SearchValue 搜索值
	// 当类型为user时,搜索值为用户名(支持模糊搜索),e.g.:张三
	// 当类型为ip时,搜索用户IP段,e.g.:{"start":"1.1.1.1","end":"1.1.1.10"}
	// 当类型为mac时,搜索用户绑定mac地址,e.g.:ee-ee-ee-ee-ee-ee
	SearchValue interface{} `json:"search_value"`
	Extend      struct {
		FatherPath string            `json:"father_path,omitempty"` // 指定搜索father_path组中的用户,默认为"/"
		CustomCfg  map[string]string `json:"custom_cfg,omitempty"`  // 自定义属性的键值对(不支持同时搜索多个自定义属性)
		UserStatus string            `json:"user_status,omitempty"` // 用户状态(共有3种,all:启用和禁用 enabled:启用 disabled:禁用,默认为"all")
		Public     bool              `json:"public,omitempty"`      // true:搜索过滤出允许多人同时使用的帐号,默认为false
		Expire     struct {
			Start string `json:"start,omitempty"`
			End   string `json:"end,omitempty"`
		} `json:"expire,omitempty"` // 账号过期时间(start:起始时间 end:结束时间 start和end成 对出现,组成时间段)
	} `json:"extend,omitempty"` // 搜索扩展字段
}

// UserSearch 搜索用户
func (ac *AC) UserSearch(data UserSearch) ([]UserDetail, error) {
	var (
		req = &acReq{
			uri:    ac.baseUrl + acUser,
			method: acPost,
			Query:  map[string]string{"_method": "GET"},
		}
		postData = make(map[string]interface{})
	)
	jb, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jb, &postData)
	if err != nil {
		return nil, err
	}
	req.Data = postData
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)
	var r []UserDetail
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// UserSearch 用户搜索传入结构体(最多返回100个)
type UserMod struct {
	Name string `json:"name"` // need mod username
	Data struct {
		Desc       string `json:"desc,omitempty"`
		ExpireTime string `json:"expire_time,omitempty"`
		Extend     struct {
			FatherPath string            `json:"father_path,omitempty"` // 指定搜索father_path组中的用户,默认为"/"
			CustomCfg  map[string]string `json:"custom_cfg,omitempty"`  // 自定义属性的键值对(不支持同时搜索多个自定义属性)
			UserStatus string            `json:"user_status,omitempty"` // 用户状态(共有3种,all:启用和禁用 enabled:启用 disabled:禁用,默认为"all")
			Public     bool              `json:"public,omitempty"`      // true:搜索过滤出允许多人同时使用的帐号,默认为false
			Expire     struct {
				Start string `json:"start,omitempty"`
				End   string `json:"end,omitempty"`
			} `json:"expire,omitempty"` // 账号过期时间(start:起始时间 end:结束时间 start和end成 对出现,组成时间段)
		} `json:"extend,omitempty"` // 搜索扩展字段
	} `json:"data,omitempty"` // need mod userinfo
}

//UserMod 修改用户信息 test ok
func (ac *AC) UserMod(modInfo UserMod) (string, error) {
	req := &acReq{
		uri:    ac.baseUrl + acUser,
		method: acPost,
		Query:  map[string]string{"_method": "PUT"},
	}

	var (
		postData = make(map[string]interface{})
		r        string
	)

	jb, err := json.Marshal(modInfo)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(jb, &postData)
	if err != nil {
		return "", err
	}
	req.Data = postData
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)

	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return r, nil
}

// UserGet 获取用户详细信息
func (ac *AC) UserGet(name string) (*UserDetail, error) {
	var req = &acReq{
		uri: ac.baseUrl + acUser, method: acGet,
		Query: map[string]string{"name": name},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)
	var r *UserDetail
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// UserPolicySet 设置用户上网/流控策略结构体
type UserPolicySet struct {
	Opr    string   `json:"opr"`    // 操作(add:在原策略增加,del:在原有策略删除,modify:将 策略设置为policy字段所指定的,会清除原有策略)
	User   string   `json:"user"`   // 需要修改策略的用户
	Policy []string `json:"policy"` // 策略名列表
}

// UserNetPolicySet 设置用户的上网策略,返回成功提示或错误
func (ac *AC) UserNetPolicySet(set UserPolicySet) (string, error) {
	var (
		req      = &acReq{uri: ac.baseUrl + acUserNetPolicy, method: acPost}
		postData = make(map[string]interface{})
	)
	jb, err := json.Marshal(set)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(jb, &postData)
	if err != nil {
		return "", err
	}
	req.Data = postData
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

//// UserNetPolicySet 设置用户的上网策略,返回成功提示或错误
//func (ac *AC) UserNetPolicyGetInfo(username string) (string, error) {
//	var (
//		req      = &acReq{uri: ac.baseUrl + acUserNetPolicy, method: acGet}
//		postData = make(map[string]interface{})
//	)
//	jb, err := json.Marshal(UserPolicySet{Opr: "get",User: username})
//	if err != nil {
//		return "", err
//	}
//	err = json.Unmarshal(jb, &postData)
//	if err != nil {
//		return "", err
//	}
//	req.Data = postData
//	dataBytes, err := ac.send(req)
//	if err != nil {
//		return "", err
//	}
//	if len(dataBytes) == 0 {
//		return "", errors.New(acErrNoData)
//	}
//	var resp = &acResp{}
//	err = json.Unmarshal(dataBytes, resp)
//	if err != nil {
//		return "", err
//	}
//	if resp.Code != 0 {
//		return "", errors.New(resp.Message)
//	}
//	return resp.Data.(string), nil
//}

// UserNetPolicyGet 获取用户关联的策略列表
// FIXME:单元测试报错(请求的接口数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) UserNetPolicyGet(username string) ([]string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acUserNetPolicy,
		method: acGet,
		Query:  map[string]string{"user": username},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r []string
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// UserFluxPolicySet 设置用户流控策略
func (ac *AC) UserFluxPolicySet(set UserPolicySet) (string, error) {
	var (
		req      = &acReq{uri: ac.baseUrl + acUserFluxPolicy, method: acPost}
		postData = make(map[string]interface{})
	)
	jb, err := json.Marshal(set)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(jb, &postData)
	if err != nil {
		return "", err
	}
	req.Data = postData
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// UserFluxPolicyGet 传入用户名获取其关联的策略列表
// FIXME:单元测试报错(请求的接口数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) UserFluxPolicyGet(username string) ([]string, error) {
	dataBytes, err := ac.send(&acReq{uri: ac.baseUrl + acUserFluxPolicy, method: acGet, Query: map[string]string{"user": username}})
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r []string
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// UserVerifyPassword 验证本地用户密码
// FIXME: 单元测试失败,接口文档有问题,实际调用的是获取用户详细信息接口
func (ac *AC) UserVerifyPassword(username, password string) error {
	var req = &acReq{
		uri:    ac.baseUrl + acUser,
		method: acGet,
		Query: map[string]string{
			"_method":  "verify",
			"name":     username,
			"password": password,
		},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return err
	}
	if len(dataBytes) == 0 {
		return errors.New(acErrNoData)
	}
	var r []string
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New(resp.Message)
	}
	return nil
}



// GroupAdd 添加组
// path:要添加的组路径,最多支持15层级目录创建(以"/"开头,且不支持向域 用户组添加组)
// desc:组描述
func (ac *AC) GroupAdd(path string, desc ...string) (string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acGroup,
		method: acPost,
		Data:   map[string]interface{}{"path": path},
	}
	if len(desc) > 0 {
		req.Data["desc"] = desc[0]
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// GroupDelete 删除已存在的组
// path:要删除的组名(以"/"开头)
func (ac *AC) GroupDelete(path string) (string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acGroup,
		method: acPost,
		Query:  map[string]string{"_method": "DELETE"},
		Data:   map[string]interface{}{"path": path},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// GroupPut 修改组信息(只能修改组描述信息)
func (ac *AC) GroupPut(path string, desc string) (string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acGroup,
		method: acPost,
		Query:  map[string]string{"_method": "PUT"},
		Data:   map[string]interface{}{"path": path, "desc": desc},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// GroupPolicySet 设置组上网/流控策略结构体
type GroupPolicySet struct {
	Opr    string   `json:"opr"`    // 操作(add:在原策略增加,del:在原有策略删除,modify:将 策略设置为policy字段所指定的,会清除原有策略)
	Group  string   `json:"group"`  // 需要修改策略的组
	Policy []string `json:"policy"` // 策略名列表
}

// GroupNetPolicySet 指定/修改/删除组关联的上网策略
func (ac *AC) GroupNetPolicySet(plc GroupPolicySet) (string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acGroupNetPolicy,
		method: acPost,
	}
	plcJson, err := json.Marshal(plc)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(plcJson, &req.Data)
	if err != nil {
		return "", err
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// GroupNetPolicyGet 获取对应组关联的上网策略
// FIXME:单元测试报错(请求的接口数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) GroupNetPolicyGet(path string) ([]string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acGroupNetPolicy,
		method: acGet,
		Query: map[string]string{
			"path": path,
		},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r []string
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// NetPolicy 上网策略结构
type NetPolicy struct {
	PolicyInfo NetPolicyInfo     `json:"policy_info,omitempty"` // 策略信息
	UserInfo   NetPolicyUserInfo `json:"user_info,omitempty"`   // 策略关联的用户信息
}

type NetPolicyInfo struct {
	Name    string `json:"name,omitempty"`    // 策略名
	Type    string `json:"type,omitempty"`    // 策略类型
	Founder string `json:"founder,omitempty"` // 策略创建者
	Expire  string `json:"expire,omitempty"`  // 过期时间
	Status  bool   `json:"status,omitempty"`  // 是否启用
	Depict  string `json:"depict,omitempty"`  // 策略描述信息
}

type NetPolicyUserInfo struct {
	Ou          []string `json:"ou,omitempty"`            // 在线用户信息
	Aduser      []string `json:"aduser,omitempty"`        // 域用户信息
	Adgroup     []string `json:"adgroup,omitempty"`       // 域安全组信息
	ExcAduser   []string `json:"exc_aduser,omitempty"`    // 排除域用户信息
	Attribute   []string `json:"attribute,omitempty"`     // 域属性信息
	UserAttrGrp []string `json:"user_attr_grp,omitempty"` // 用户,组属性信息
	Sourceip    []string `json:"sourceip,omitempty"`      // 源IP
	Location    []string `json:"location,omitempty"`      // 位置列表
	Terminal    []string `json:"terminal,omitempty"`      // 终端列表
	TargetArea  []string `json:"target_area,omitempty"`   // 目标区域
	Local       string   `json:"local,omitempty"`         // 关联(适用)的用户
}

// PolicyNetGet 获取设备已有上网策略信息
func (ac *AC) PolicyNetGet() ([]NetPolicy, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acNetPolicy,
		method: acGet,
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)
	var r []NetPolicy
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// FluxPolicy 流控策略结构
// FIXME:注释中的字段均为API文档中有但实际请求中不一致或不存在的值,需厂商更新API(深信服垃圾)
type FluxPolicy struct {
	Id         string   `json:"id"`                // 通道ID
	Name       string   `json:"name"`              // 通道名
	FatherId   string   `json:"father_id"`         // 父通道名称
	IpGroup    string   `json:"di,omitempty"`      // 目标IP组(多个逗号分隔)
	Object     string   `json:"object,omitempty"`  // 适用对象(多个逗号分隔,位置/用户/终端...)
	Service    string   `json:"service,omitempty"` // 适用应用(多个逗号分隔)
	ActiveTime string   `json:"time,omitempty"`    // 生效时间(e.g.:全天)
	Status     bool     `json:"status,omitempty"`  // 策略是否启用,true:启用,false:禁用
	Assured    []string `json:"assured,omitempty"` // 保证带宽，数组包含上行和下行，-1表示无限制
	Max        []string `json:"max,omitempty"`     // 最大带宽，数组包含上行和下行，-1表示无限制
	Single     []string `json:"single,omitempty"`  // 单用户限制带宽，数组包含上行和下行，-1表示无限制
	//IsDefaultChild bool          `json:"is_default_child,omitempty"` // 是否为默认通道,true:是默认通道,false:不是默认通道
	//Childrens      []*FluxPolicy `json:"childrens,omitempty"`        // 子通道对象数组
	//IsLowSpeed     []string      `json:"is_low_speed,omitempty"`     // 域属性信息
	//TargetUsers    string        `json:"target_users,omitempty"`     // 目标用户(多个用户逗号分隔)
	//IpGroup        string        `json:"ip_group,omitempty"`         // 目标IP组(多组逗号分隔)
}

// PolicyFluxGet 获取设备已有流控策略信息
func (ac *AC) PolicyFluxGet() ([]FluxPolicy, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acFluxPolicy,
		method: acGet,
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)
	var r []FluxPolicy
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return r, nil
}

// BindUserSearch 查询用户和IP/MAC的绑定关系(支持按用户名,IP,MAC进行搜索)
// FIXME:单元测试报错(请求的数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) BindUserSearch(val string) error {
	var req = &acReq{
		uri:    ac.baseUrl + acBindInfoUser,
		method: acGet,
		Query:  map[string]string{"search": val},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return err
	}
	if len(dataBytes) == 0 {
		return errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)
	var r []FluxPolicy
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New(resp.Message)
	}
	return nil
}

// BindUser 用户绑定结构体
type BindUser struct {
	Name     string `json:"name"`                // 用户名
	Enable   bool   `json:"enable"`              // 是否启用
	Desc     string `json:"desc,omitempty"`      // 描述信息
	AddrType string `json:"addr_type,omitempty"` // 绑定类型,(ip/mac/ipmac)
	// Addr 绑定对象
	// 当 AddrType 为ip时,取值为ip地址(e.g.:192.168.1.1)
	// 当 AddrType 为mac时,取值为mac地址(e.g.:ff-ff-ff-ff-ff-ff)
	// 当 AddrType 为ipmac时,取值为ipmac地址(e.g.:192.168.1.1+ff-ff-ff-ff-ff-ff)
	Addr       string `json:"addr,omitempty"`
	Limitlogon bool   `json:"limitlogon,omitempty"` // 是否限制登录
	Noauth     struct {
		Enable     bool `json:"enable"`      // 是否启用免认证
		ExpireTime int  `json:"expire_time"` // Unix时间戳，为0表示永不过期，>0表示过期时 间戳
	} `json:"noauth,omitempty"`
}

// BindUserAdd 增加用户的IP/MAC绑定
// FIXME:单元测试报错(请求的接口数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) BindUserAdd(data BindUser) (string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acBindInfoUser,
		method: acPost,
	}
	dataJson, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(dataJson, &req.Data)
	if err != nil {
		return "", err
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

// BindUserDel 删除用户和IP/MAC的绑定关系
// FIXME:单元测试报错(请求的接口数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) BindUserDel(addr string) (string, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acBindInfoUser,
		method: acPost,
		Query:  map[string]string{"_method": "DELETE"},
		Data:   map[string]interface{}{"addr": addr},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return "", err
	}
	if len(dataBytes) == 0 {
		return "", errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", errors.New(resp.Message)
	}
	return resp.Data.(string), nil
}

type BindIpMac struct {
	Ip   string `json:"ip,omitempty"`   // IP
	Mac  string `json:"mac,omitempty"`  // MAC
	Desc string `json:"desc,omitempty"` // 描述
}

// BindIpmacSearch 查询IPMac绑定关系(支持按ip/mac进行搜索)
// 如果没有查询到则会返回错误
func (ac *AC) BindIpmacSearch(val string) (*BindIpMac, error) {
	var req = &acReq{
		uri:    ac.baseUrl + acBindInfoIpMac,
		method: acGet,
		Query:  map[string]string{"search": val},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	dataBytes = acFixJson(dataBytes)
	var r BindIpMac
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return &r, nil
}

// BindIpmacAdd 增加IP/MAC绑定信息
func (ac *AC) BindIpmacAdd(bind BindIpMac) error {
	var (
		err error
		req = &acReq{
			uri:    ac.baseUrl + acBindInfoIpMacOp,
			method: acPost,
		}
	)
	if bind.Ip == "" || bind.Mac == "" {
		return errors.New(acErrArgCheck)
	}
	req.Data, err = acTransJsonMap(bind)
	if err != nil {
		return err
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return err
	}
	if len(dataBytes) == 0 {
		return errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New(resp.Message)
	}
	return nil
}

// BindIpmacDel 删除IP/MAC绑定信息
func (ac *AC) BindIpmacDel(ip string) error {
	var req = &acReq{
		uri:    ac.baseUrl + acBindInfoIpMacOp,
		method: acPost,
		Query:  map[string]string{"_method": "DELETE"},
		Data:   map[string]interface{}{"ip": ip},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return err
	}
	if len(dataBytes) == 0 {
		return errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New(resp.Message)
	}
	return nil
}

// OnlineUserGet 获取设备在线用户过滤结构体
type OnlineUserGet struct {
	Status string `json:"status,omitempty"` // Status 用户状态(all-所有,frozen-已冻结,active-活跃)
	// Terminal 终端类型
	// all-所有 pc-PC用户 mobile-移动终端
	// multi-多终端 iot-哑终端 armarium-医疗设备 custom-用户自定义设备
	Terminal string               `json:"terminal,omitempty"`
	Filter   *OnlineUserGetFilter `json:"filter,omitempty"` // 搜索条件,为空表示所有
}

type OnlineUserGetFilter struct {
	Type  string   `json:"type,omitempty"`  // 搜索类型(user-用户组名,ip-IP地址数组,mac-mac地址数组)
	Value []string `json:"value,omitempty"` // 与搜索类型对应的值数组(用户名支持模糊查询)
}

type OnlineUsers struct {
	Count int          `json:"count"`
	Users []OnlineUser `json:"users,omitempty"` // 在线用户对象数组，最多返回100个用户
}

type OnlineUser struct {
	Name       string `json:"name,omitempty"`
	ShowName   string `json:"show_name,omitempty"`
	FatherPath string `json:"father_path,omitempty"`
	Group      string `json:"group,omitempty"`
	Ip         string `json:"ip,omitempty"`
	Mac        string `json:"mac,omitempty"`
	Terminal   int    `json:"terminal,omitempty"`
	Authway    int    `json:"authway,omitempty"`
	LoginTime  int    `json:"login_time,omitempty"`
	OnlineTime int    `json:"online_time,omitempty"`
}

// OnlineUserGet 获取在线用户列表
func (ac *AC) OnlineUserGet(filter OnlineUserGet) (*OnlineUsers, error) {
	var (
		err error
		req = &acReq{
			uri:    ac.baseUrl + acOnlineUsers,
			method: acPost,
			Query:  map[string]string{"_method": "GET"},
		}
	)
	req.Data, err = acTransJsonMap(filter)
	if err != nil {
		return nil, err
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return nil, err
	}
	if len(dataBytes) == 0 {
		return nil, errors.New(acErrNoData)
	}
	var r OnlineUsers
	var resp = &acResp{Data: &r}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, errors.New(resp.Message)
	}
	return &r, nil
}

// OnlineUserKick 强制注销在线用户
func (ac *AC) OnlineUserKick(ip string) error {
	var req = &acReq{
		uri:    ac.baseUrl + acOnlineUsers,
		method: acPost,
		Query:  map[string]string{"_method": "DELETE"},
		Data:   map[string]interface{}{"ip": ip},
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return err
	}
	if len(dataBytes) == 0 {
		return errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New(resp.Message)
	}
	return nil
}

// OnlineUserUp 上线在线用户(单点登录)
type OnlineUserUp struct {
	Ip       string `json:"ip"`
	Name     string `json:"name"`
	ShowName string `json:"show_name"`
	Group    string `json:"group"`
	Mac      string `json:"mac"`
}

// OnlineUserUp 上线在线用户(单点登录)
// FIXME:单元测试报错(请求的接口数据格式不正确!),需联系厂家获取正确参数
func (ac *AC) OnlineUserUp(user OnlineUserUp) error {
	var (
		err error
		req = &acReq{
			uri:    ac.baseUrl + acOnlineUsers,
			method: acPost,
		}
	)
	req.Data, err = acTransJsonMap(user)
	if err != nil {
		return err
	}
	dataBytes, err := ac.send(req)
	if err != nil {
		return err
	}
	if len(dataBytes) == 0 {
		return errors.New(acErrNoData)
	}
	var resp = &acResp{}
	err = json.Unmarshal(dataBytes, resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New(resp.Message)
	}
	return nil
}

type acReq struct {
	uri    string
	method string
	Query  map[string]string
	Data   map[string]interface{}
}

type acResp struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func (ac *AC) send(req *acReq) ([]byte, error) {
	var (
		dataBytes   []byte
		err         error
		random, key = ac.setRandomKey()
	)
	if req.Query != nil && len(req.Query) > 0 {
		if strings.Index(req.uri, "?") == -1 {
			req.uri += "?"
		} else {
			req.uri += "&"
		}
		var qlist []string
		for k, v := range req.Query {
			qlist = append(qlist, fmt.Sprintf("%s=%s", k, v))
		}
		req.uri += strings.Join(qlist, "&")
	}

	if strings.ToUpper(req.method) == "GET" {
		if strings.Index(req.uri, "?") == -1 {
			req.uri += "?"
		} else {
			req.uri += "&"
		}
		queryList := []string{
			fmt.Sprintf("%s=%s", "random", random),
			fmt.Sprintf("%s=%s", "md5", key),
		}
		req.uri += strings.Join(queryList, "&")
	}

	if strings.ToUpper(req.method) == "POST" {
		if req.Data == nil {
			req.Data = make(map[string]interface{})
		}
		req.Data["random"] = random
		req.Data["md5"] = key
		dataBytes, err = json.Marshal(req.Data)
		if err != nil {
			return nil, err
		}
	}

	httpReq, err := http.NewRequest(req.method, req.uri, bytes.NewBuffer(dataBytes))
	if err != nil {
		return nil, err
	}
	if ac.ErrLangCN {
		httpReq.Header.Set("Accept-Language", "zh-CN")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	log.Println(req.uri)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Println(string(body))
	if len(body) == 0 {
		return nil, errors.New("response nil")
	}
	return body, nil
}

func (ac *AC) setRandomKey() (string, string) {
	rand.Seed(time.Now().Unix())
	var (
		md5Handler = md5.New()
		rd         = fmt.Sprint(rand.Uint64())
		sec        = ac.secret + rd
	)

	io.WriteString(md5Handler, sec)
	return rd, fmt.Sprintf("%x", md5Handler.Sum(nil))
}

func acTransJsonMap(src interface{}) (map[string]interface{}, error) {
	var r = make(map[string]interface{})
	bingJ, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bingJ, &r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// acFixJson 深信服AC的api接口中很多类型是字符串数组的空值[],但是返回为{},导致json解析失败
// 此方法临时做替换修复该问题
func acFixJson(data []byte) []byte {
	rplcer := strings.NewReplacer(
		`"bind_cfg":{}`, `"bind_cfg":[]`,
		`"ipmac":{}`, `"ipmac":[]`,
		`"ou":{}`, `"ou":[]`,
		`"aduser":{}`, `"aduser":[]`,
		`"adgroup":{}`, `"adgroup":[]`,
		`"exc_aduser":{}`, `"exc_aduser":[]`,
		`"attribute":{}`, `"attribute":[]`,
		`"user_attr_grp":{}`, `"user_attr_grp":[]`,
		`"sourceip":{}`, `"sourceip":[]`,
		`"location":{}`, `"location":[]`,
		`"terminal":{}`, `"terminal":[]`,
		`"target_area":{}`, `"target_area":[]`,
		`"value":{}`, `"value":[]`,
	)
	return []byte(rplcer.Replace(string(data)))
}
