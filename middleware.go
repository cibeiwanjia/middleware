package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/gogf/gf/v2/net/ghttp"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	Id       int64  `json:"id"`       // 用户ID
	Username string `json:"username"` // 用户名
	App      string `json:"app"`      // 登录应用（如admin、app、web）
}

type Claims struct {
	User *User `json:"user"`
	jwt.RegisteredClaims
}

type TokenConfig struct {
	SecretKey string // JWT签名密钥（建议32位以上字符串）
	Expires   int64  // JWT过期时间（单位：秒）
}

var (
	config     *TokenConfig
	errorLogin = gerror.New("登录身份已失效，请重新登录！")
)

func SetConfig(c *TokenConfig) {
	config = c
}

func Login(ctx context.Context, user *User) (string, error) {
	// 校验配置是否初始化
	if config == nil || config.SecretKey == "" {
		return "", gerror.New("JWT配置未初始化，请先调用SetConfig方法")
	}
	if user == nil || user.Id <= 0 || user.Username == "" {
		return "", gerror.New("用户信息不完整")
	}

	// 获取当前时间
	now := gtime.Now()
	// 构造JWT载荷
	claims := Claims{
		User: user,
		RegisteredClaims: jwt.RegisteredClaims{
			// JWT过期时间：当前时间 + 配置的过期时长（直接使用.Time属性获取标准time.Time）
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Second * time.Duration(config.Expires)).Time),
			// JWT签发时间
			IssuedAt: jwt.NewNumericDate(now.Time),
		},
	}

	// 使用HS256算法生成JWT令牌
	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(config.SecretKey))
	if err != nil {
		g.Log().Errorf(ctx, "JWT令牌生成失败：%v", err)
		return "", err
	}

	// 登录成功日志埋点
	LoginLog(ctx, user, tokenStr, "登录成功")
	return tokenStr, nil
}

// ParseToken 解析并验证JWT令牌有效性
func ParseToken(ctx context.Context, tokenStr string) (*User, error) {
	// 校验配置是否初始化
	if config == nil || config.SecretKey == "" {
		return nil, gerror.New("JWT配置未初始化，请先调用SetConfig方法")
	}
	if tokenStr == "" {
		return nil, errorLogin
	}

	// 解析JWT令牌
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否为HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, gerror.New(fmt.Sprintf("不支持的JWT签名算法：%v", token.Header["alg"]))
		}
		return []byte(config.SecretKey), nil
	})

	// 解析失败处理（认证失败）
	if err != nil {
		AuthLog(ctx, tokenStr, err, "认证失败", nil)
		return nil, errorLogin
	}

	// 验证令牌有效性并提取用户信息
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid || claims.User == nil || claims.User.Id <= 0 {
		AuthLog(ctx, tokenStr, gerror.New("JWT令牌无效或用户信息为空"), "认证失败", nil)
		return nil, errorLogin
	}

	// 认证成功日志埋点
	AuthLog(ctx, tokenStr, nil, "认证成功", claims.User)
	return claims.User, nil
}

// LoginLog 登录日志埋点
func LoginLog(ctx context.Context, user *User, jwtToken string, msg string) {
	logData := g.Map{
		"oper_type": "user_login",
		"user_id":   user.Id,
		"username":  user.Username,
		"app":       user.App,
		"jwt_token": gstr.SubStr(jwtToken, 0, 20) + "...", // JWT脱敏展示
		"oper_time": gtime.Now().Format("Y-m-d H:i:s"),
		"message":   msg,
	}
	g.Log().Infof(ctx, "【登录日志】%+v", logData)
}

// AuthLog 接口认证日志埋点（成功/失败通用）
func AuthLog(ctx context.Context, jwtToken string, err error, msg string, user *User) {
	// 初始化默认用户信息
	userInfo := &User{
		Id:       0,
		Username: "未知用户",
		App:      "未知应用",
	}

	// 认证成功：直接使用传入的用户信息
	if user != nil {
		userInfo = user
	} else if jwtToken != "" && err != nil {
		// 认证失败：尝试解析JWT获取用户信息（仅做日志补充，不影响业务）
		claims := &Claims{}
		// 忽略解析错误，仅提取可用信息
		_, parseErr := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.SecretKey), nil
		})
		if parseErr == nil && claims.User != nil && claims.User.Id > 0 {
			userInfo = claims.User
		}
	}

	// 构造日志数据
	logData := g.Map{
		"oper_type": "api_auth",
		"user_id":   userInfo.Id,
		"username":  userInfo.Username,
		"app":       userInfo.App,
		"jwt_token": gstr.SubStr(jwtToken, 0, 20) + "...",
		"oper_time": gtime.Now().Format("Y-m-d H:i:s"),
		"message":   msg,
	}

	// 错误日志/信息日志区分输出
	if err != nil {
		logData["error_msg"] = err.Error()
		g.Log().Errorf(ctx, "【认证日志】%+v", logData)
	} else {
		g.Log().Infof(ctx, "【认证日志】%+v", logData)
	}
}

// LogoutLog 注销日志埋点
func LogoutLog(ctx context.Context, jwtToken string, msg string) {
	// 解析JWT获取用户信息
	user, _ := ParseToken(ctx, jwtToken)
	if user == nil {
		user = &User{
			Id:       0,
			Username: "未知用户",
			App:      "未知应用",
		}
	}

	logData := g.Map{
		"oper_type": "user_logout",
		"user_id":   user.Id,
		"username":  user.Username,
		"app":       user.App,
		"oper_time": gtime.Now().Format("Y-m-d H:i:s"),
		"message":   msg,
	}
	g.Log().Infof(ctx, "【注销日志】%+v", logData)
}

// GetJwtFromRequest 从请求头/URL参数中获取JWT令牌
func GetJwtFromRequest(r *ghttp.Request) string {

	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		return gstr.Replace(authHeader, "Bearer ", "")
	}

	return r.Get("jwt").String()
}

func JwtDemoRun(customConfig *TokenConfig, customUser *User) (string, *User, error) {

	var jwtConfig *TokenConfig
	if customConfig != nil {
		jwtConfig = customConfig
	} else {
		jwtConfig = &TokenConfig{
			SecretKey: "my_jwt_secret_key_32bit_12345678", // 默认签名密钥
			Expires:   3600,                               // 默认1小时过期
		}
	}
	SetConfig(jwtConfig)

	// 2. 准备用户信息（优先使用自定义用户，无则用默认测试用户）
	var testUser *User
	if customUser != nil {
		testUser = customUser
	} else {
		testUser = &User{
			Id:       1001,
			Username: "zhangsan",
			App:      "admin",
		}
	}

	// 3. 生成JWT令牌
	ctx := context.Background()
	jwtToken, err := Login(ctx, testUser)
	if err != nil {
		return "", nil, fmt.Errorf("登录失败：%w", err)
	}
	fmt.Printf("JWT令牌生成成功：%s\n\n", jwtToken)

	// 4. 解析并验证JWT令牌
	userInfo, err := ParseToken(ctx, jwtToken)
	if err != nil {
		return "", nil, fmt.Errorf("JWT认证失败：%w", err)
	}
	fmt.Printf("JWT认证成功，解析用户信息：%+v\n\n", userInfo)

	// 5. 模拟注销，输出注销日志
	LogoutLog(ctx, jwtToken, "注销成功")

	return jwtToken, userInfo, nil
}

func main() {
	_, _, err := JwtDemoRun(nil, nil)
	if err != nil {
		fmt.Printf("JWT流程执行失败：%v\n", err)
		return
	}
}
