namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Users;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;
    private readonly IUltilitiesService _ultilitiesService;

    public UsersController(IUserService userService, IUltilitiesService ultilitiesService)
    {
        _userService = userService;
        _ultilitiesService = ultilitiesService;
    }

    [AllowAnonymous]
    [HttpPost("[action]")]
    public async Task<IActionResult> Authenticate(AuthenticateRequest model)
    {
        var response = await _userService.Authenticate(model);
        return Ok(response);
    }

    [Authorize(Role.Admin)]
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var users = await _userService.GetAll();
        var usersSameLocation = users.Where(u => u.Location.Equals(currentAdmin?.Location));
        return Ok(usersSameLocation);
    }

    [HttpPut("firsttimepassword")]
    public async Task<IActionResult> ChangePasswordFirstTime(ChangePasswordRequest model)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (model.Id != currentUser?.Id) return Unauthorized(new { message = "Permission are not allowed" });
        if (currentUser.IsFirstLogin == false)
        {
            await _userService.Logout(mwi.Exp, mwi.Token);
            return BadRequest(new { message = "You already changed your password" });
        }

        await _userService.UpdatePasswordFirstTime(model);
        return Ok();
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetById(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        // only admins can access other user records
        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (id != currentUser?.Id && currentUser?.Type != Role.Admin) return Unauthorized(new { message = "Unauthorized" });

        var user = await _userService.GetById(id);
        if (user.Location.Equals(currentUser.Location))
        {
            return Ok(user);
        }
        else
        {
            return Unauthorized("Can not view detail of Staff with different location");
        }

    }

    [Authorize(Role.Admin)]
    [HttpPost]
    public async Task<IActionResult> CreateNewUser(UserCreateModel user)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin?.Type != Role.Admin) return Unauthorized(new { message = "Unauthorized" });
        if (currentAdmin.Location == null) return Unauthorized(new { message = "Unauthorized" });

        var newUser = await _userService.CreateUser(user, currentAdmin.Location.ToString(), currentAdmin.Id);
        return Ok(newUser);
    }

    [Authorize(Role.Admin)]
    [HttpPut]
    public async Task<IActionResult> UpdateUser(UserUpdateModel user)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin?.Type != Role.Admin) return Unauthorized(new { message = "Unauthorized" });
        if (currentAdmin.Location == null) return Unauthorized(new { message = "Unauthorized" });

        await _userService.UpdateUser(user, currentAdmin.Location.ToString());
        return Ok();
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        //if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _userService.Logout(mwi.Exp, mwi.Token);
        await _userService.DeleteExpirationDateToken();

        return Ok();
    }

    // STILL WORKING ON THIS!!!
    [Authorize(Role.Admin)]
    [HttpDelete]
    public async Task<IActionResult> DeleteUser(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Id == id) return BadRequest(new { message = "You can not disable yourself" });
        await _userService.DeleteUser(id);
        return Ok();
    }

    [HttpPut("password")]
    public async Task<IActionResult> UpdatePassword(PasswordRequest model)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _userService.UpdatePassword(model.OldPassword, model.NewPassword, currentUser.Id);
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpGet("pagination")]
    public async Task<IActionResult> GetAllPagination(string? filter = null, string? search = null, string? sort = null, string? sortTerm = "staffcode", int page = 1, int pageSize = 10)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var users = await _userService.GetAll();
        var usersSameLocation = users.Where(u => u.Location.Equals(currentAdmin?.Location));
        var pagination = _ultilitiesService.GetUserResults(usersSameLocation, filter, search, sort, sortTerm, page, pageSize);
        return Ok(pagination);
    }
}