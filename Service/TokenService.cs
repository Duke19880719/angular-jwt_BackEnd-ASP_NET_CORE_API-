// 引入自訂 Model 類別
using angular_jwt_BackEnd_ASP_NET_CORE_API_.Model;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
//用於建立、解析和驗證 JWT（JSON Web Token）
using System.IdentityModel.Tokens.Jwt;
//提供 Claim、ClaimsIdentity、ClaimsPrincipal 等類型，用於表示使用者身份與權限。
using System.Security.Claims;
//包含各種加密功能，如 RSA、SHA256、Aes
using System.Security.Cryptography;
//文字編碼功能，如 Encoding.UTF8、StringBuilder 等。
using System.Text;


//一個 JWT 長這樣：

//xxxxx.yyyyy.zzzzz

//它分成三部分：
//部分	            內容
//Header	            算法、類型（alg、typ）
//Payload	Claims      （使用者身份資訊）
//Signature	        簽名保護（確保沒被竄改）

namespace angular_jwt_BackEnd_ASP_NET_CORE_API_.Service
{   
    //1.創建access token 
    //2.創建refresh token
    public class TokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //createAccessToken流程
        //取得 Key → 建立對稱式密鑰
        //用 Key + 演算法 → 建立 SigningCredentials
        //交給 JwtSecurityToken → 生成 Token（Header.Payload.Signature）
        public (string Token,long Exp) createAccessToken(string user_name,string role)
        {
            //new Claim(ClaimTypes.Name, username)
            //ClaimTypes.Name 是一個預定義的 claim type，代表使用者名稱。
            //username 是變數，存放要放進 token 的使用者名稱。
            //把使用者名稱存進 JWT，之後可以透過 token 取得使用者身分。

            //new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            //JwtRegisteredClaimNames.Jti 是 JWT 標準註冊的 claim type，代表 JWT ID。
            //Guid.NewGuid().ToString() 生成一個唯一識別碼，用來標記這個 token。
            //這可以防止 token 重複使用（增加安全性）。
            var claims = new[]
            {
                //new Claim("欄位名稱", "欄位的值")
                new Claim(ClaimTypes.Name, user_name),
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //建立對稱式密鑰，使用 UTF-8 編碼 appsettings.json 中的 "Jwt:Key"
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            //建立簽名憑證，使用 HMAC SHA256 演算法做簽名
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //DateTime.UtcNow 是 C# 用來取得現在的世界標準時間（UTC, Coordinated Universal Time）
            //也就是不受時區影響的時間。
            var expires = DateTime.UtcNow.AddSeconds(10);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: credentials
            );

            //JwtSecurityTokenHandler().WriteToken(token)
            //把 JWT 物件「打包成可傳輸、可認證的標準 JWT 字串」。
            //DateTimeOffset(expires).ToUnixTimeSeconds()轉成 Unix 時間戳（秒數）。
            return (new JwtSecurityTokenHandler().WriteToken(token),
                new DateTimeOffset(expires).ToUnixTimeSeconds());
        }

        //createRefreshToken流程
        //生成 隨機 bytes → 變成 token
        //設定 過期時間 → UTC + 2 分鐘
        //將 token 轉 Base64 → 可傳給前端
        //將 expiry 轉 Unix 秒數 → 前端/後端判斷有效性
        public (string Token, long Exp) createRefreshToken()
        {
            var randomNumber = new byte[32];

            //using(){} 的簡寫，會自動釋放資源。
            //作用域：rng 從宣告處開始，到它所在的整個作用域結束
            //如果在方法裡，rng 的作用域就是整個方法
            //如果在區塊 { }裡，作用域就是那個區塊
            using var rng = RandomNumberGenerator.Create();

            //把隨機數填入你傳入的陣列裡
            rng.GetBytes(randomNumber);

            var expires = DateTime.UtcNow.AddSeconds(20);

            //把隨機數轉成 Base64 字串，作為 refresh token。
            return (Convert.ToBase64String(randomNumber),
                new DateTimeOffset(expires).ToUnixTimeSeconds());
        }

        //後端自己用，從「過期的 access token」中取出使用者身分，用來重新發 token
        //接收一顆「已過期的 Access Token」
        //仍然驗證簽章
        //確保 token 沒被竄改
        //忽略過期時間（exp）
        //解析 token payload
        //轉成 ClaimsPrincipal
        //回傳給 後端程式碼
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            //ValidateAudience         檢查 token 是否是給該 API
            //ValidateIssuer           檢查 signing server
            //ValidateIssuerSigningKey 簽名正確性檢查;
            //ValidateLifetime         檢查是否過期 / 尚未生效
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //不驗證 Audience
                ValidateIssuer = false,   //不驗證 Issuer
                ValidateIssuerSigningKey = true, //驗證簽章
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidateLifetime = false //忽略過期時間
            };

           var tokenHandler = new JwtSecurityTokenHandler();

             //驗證 JWT 簽章
             //解析 Payload
             //回傳 ClaimsPrincipal
             //同時輸出原始 SecurityToken
            var principal = tokenHandler
                .ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            // 確認 securityToken 是 JwtSecurityToken（JWT），
            // 並檢查簽名算法是否為 HMAC-SHA256，否則視為無效 Token
            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("無效的 Token");

            return principal;


        }


    }
}

