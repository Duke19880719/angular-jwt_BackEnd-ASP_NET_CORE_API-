namespace angular_jwt_BackEnd_ASP_NET_CORE_API_.Model
{
    //登入成功給的 access token 和 refresh token 
    public class Token_Model_Response
    {
        public string Access_Token { get; set; }
        public string Refresh_Token { get; set; }
        public long Access_Token_Expire_Time { get; set; }
        public long Refresh_Token_Expire_Time { get; set; }
        public string Role { get; set; }
    }

    public class Token_Model_Request
    {
        public string Access_Token { get; set; }
        public string Refresh_Token { get; set; }
    }

    public class Login_User_Model
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
