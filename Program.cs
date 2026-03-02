using angular_jwt_BackEnd_ASP_NET_CORE_API_.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// 註冊自訂 Service
builder.Services.AddSingleton<TokenService>();

// 設定 JWT 驗證規則
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
            ClockSkew = TimeSpan.Zero
        };
    });

//ASP.NET Core 預設使用 System.Text.Json

//預設序列化策略會將 C# 的 PascalCase 屬性轉成 camelCase

//所以 Access_Token → access_Token，下面是修正方法
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        // 不使用 camelCase，保持屬性原本大小寫
        options.JsonSerializerOptions.PropertyNamingPolicy = null;
    });
//builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AngularDev",
        policy =>
        {
            policy.WithOrigins("http://localhost:4200")
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials(); // 如果有用 cookie 才需要
        });
});


var app = builder.Build();

app.UseCors("AngularDev");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.UseAuthentication(); // 認證 (你是誰)
app.UseAuthorization();  // 授權 (你有權限嗎)

app.MapControllers();

app.Run();
