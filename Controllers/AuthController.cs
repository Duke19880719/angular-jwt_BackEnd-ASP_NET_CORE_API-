using angular_jwt_BackEnd_ASP_NET_CORE_API_.Model;
using angular_jwt_BackEnd_ASP_NET_CORE_API_.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Timers;

//待做
//Reuse Detection 重用偵測

namespace angular_jwt_BackEnd_ASP_NET_CORE_API_.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly TokenService _tokenService;

        // 模擬資料庫：Key 是 RefreshToken, Value 是 (使用者名稱, 過期時間,最大登入時間)

        //ConcurrentDictionary<TKey, TValue> ，提供 線程安全 (thread-safe) 的字典操作。它的主要特點是：
        //可以同時被多個執行緒讀寫，不會出現資料競爭（race condition）。
        //不需要使用 lock 來手動控制同步。
        //提供原子操作(atomic operations)，例如 TryAdd、TryRemove、GetOrAdd、AddOrUpdate。
        private static readonly ConcurrentDictionary<string, (string Username, string Role, DateTime RefreshExpiry, DateTime AbsoluteExpiry)> Simulation_Database = new();

        // 修正 Timer 初始化：Timer 需要 TimerCallback 委派和 dueTime、period 等參數
        private static readonly System.Threading.Timer CleanupTimer = new System.Threading.Timer(
            state =>
                /* 清理過期 refresh token 的邏輯可放這裡 */
                CleanupExpiredTokens(state)
            ,
            null,
            60000, // dueTime: 60 秒後開始
            60000  // period: 每 60 秒執行一次
        );
        // 清理方法
        private static void CleanupExpiredTokens(object? state)
        {
            var now = DateTime.UtcNow;

            foreach (var kvp in Simulation_Database)
            {
                var token = kvp.Key;
                var refreshExpiry = kvp.Value.RefreshExpiry;
                var absoluteExpiry = kvp.Value.AbsoluteExpiry;

                // 如果過期或超過最大存活時間就移除
                if (now > refreshExpiry || now > absoluteExpiry)
                {
                    Simulation_Database.TryRemove(token, out _);
                }
            }

            Console.WriteLine($"清理過期 Token 完成 - {DateTime.UtcNow}");
        }


        public AuthController(TokenService tokenService)
        {
            _tokenService = tokenService;
        }

        [HttpPost("Login")]
        public ActionResult login([FromBody] Login_User_Model login_user_data)
        {
            // 這裡直接模擬登入成功，實際應該驗證使用者名稱和密碼
            var role = login_user_data.Username.ToLower().Contains("admin") ? "Admin" : "User";
            var (access_token, access_token_exp) = _tokenService.createAccessToken(login_user_data.Username, role);

            var absoluteExpiry = DateTime.UtcNow.AddMinutes(1); // 最大壽命 1 分鐘（測試用）
            string refresh_token;
            long refresh_token_exp;

            // 確保 refresh token 唯一，避免重複
            string hash_token ;
            bool added;

            do
            {
                (refresh_token, refresh_token_exp) = _tokenService.createRefreshToken();

                hash_token = HashToken(refresh_token);

                added = Simulation_Database.TryAdd(
                    hash_token,
                    (
                        login_user_data.Username,
                        role,
                        DateTime.UnixEpoch.AddSeconds(refresh_token_exp),
                        absoluteExpiry
                    )
                );

            } while (!added);

            return Ok(new Token_Model_Response
            {
                Access_Token = access_token,
                Access_Token_Expire_Time = access_token_exp,
                Refresh_Token = refresh_token,
                Refresh_Token_Expire_Time = refresh_token_exp,
                Role = role
            });
        }


        [HttpPost("refresh")]
        public ActionResult refresh([FromBody] Token_Model_Request request)
        {
            var hash_token = HashToken(request.Refresh_Token);
            // 1️ 檢查 refresh token 是否存在
            if (!Simulation_Database.TryGetValue(hash_token, out var data_info))
                return Unauthorized("無效的 refresh token");

            // 2️ 檢查 refresh token 是否過期
            if (data_info.RefreshExpiry < DateTime.UtcNow)
            {
                Simulation_Database.TryRemove(hash_token, out _);
                return Unauthorized("refresh token 已過期");
            }

            // 2️-2 檢查是否達到最大壽命
            if (data_info.AbsoluteExpiry < DateTime.UtcNow)
            {
                Simulation_Database.TryRemove(hash_token, out _);
                return Unauthorized("refresh token 已達最大時間，請重新登入");
            }

            // 3️ 解析過期的 access token（只驗簽章，不驗 exp）
            ClaimsPrincipal principal;
            try
            {
                principal = _tokenService.GetPrincipalFromExpiredToken(request.Access_Token);
            }
            catch
            {
                return Unauthorized("無效的 access token");
            }

            var username = principal.Identity?.Name;

            if (string.IsNullOrEmpty(username))
                return Unauthorized("無效的 access token");

            // 4️ 比對 access token 與 refresh token 使用者是否一致
            if (username != data_info.Username)
                return Unauthorized("token 使用者不一致");

            // 5️ Rotation：刪除舊 refresh token
            var oldHash = HashToken(request.Refresh_Token);
            Simulation_Database.TryRemove(oldHash, out _);

            var role = data_info.Role;

            var (new_access_token, new_access_token_exp) =
                _tokenService.createAccessToken(username, role);

            //var (new_refresh_token, new_refresh_token_exp) =
            //    _tokenService.createRefreshToken();

            var absoluteExpiry = data_info.AbsoluteExpiry;

            string new_refresh_token;
            long new_refresh_token_exp;
            string newHash;

            bool added;



            do
            {
                (new_refresh_token, new_refresh_token_exp) =
                    _tokenService.createRefreshToken();

                newHash = HashToken(new_refresh_token);

                added = Simulation_Database.TryAdd(
                    newHash,
                    (
                        username,
                        role,
                        DateTime.UnixEpoch.AddSeconds(new_refresh_token_exp),
                        absoluteExpiry
                    )
                );

            } while (!added);


            return Ok(new Token_Model_Response
            {
                Access_Token = new_access_token,
                Access_Token_Expire_Time = new_access_token_exp,
                Refresh_Token = new_refresh_token,
                Refresh_Token_Expire_Time = new_refresh_token_exp,
                Role = role
            });
        }

        [Authorize]
        [HttpPost("TEST_API")]
        public ActionResult Authorize_TEST_API()
        {
            return Ok(
                new
                {
                    message = "你已經成功授權，這是受保護的 API"
                }
            );
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("TEST_Role_API")]
        public ActionResult Authorize_TEST_Role_API()
        {
            return Ok(
                new
                {
                    message = "管理員權限api 呼叫成功"
                }
            );

        }


        public static string HashToken(string refreshToken)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash( System.Text.Encoding.UTF8.GetBytes(refreshToken) );
            
            return Convert.ToBase64String(hash);
        }


    }
}


