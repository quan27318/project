namespace WebApi.Models.Users;
using WebApi.Entities;

public class MiddlewareInfo{
    public User? User {get; set;}
    public DateTime Exp {get; set;}
    public string? Token {get; set;}
}