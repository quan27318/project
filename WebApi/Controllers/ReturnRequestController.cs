namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Users;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ReturnRequestsController : ControllerBase
{
    private IReturnService _returnService;
    private IUserService _userService;
    private readonly IUltilitiesService _ultilitiesService;

    public ReturnRequestsController(IReturnService returnService, IUserService userService, IUltilitiesService ultilitiesService)
    {
        _returnService = returnService;
        _userService = userService;
        _ultilitiesService = ultilitiesService;
    }

    [HttpPost("user/{assignmentid:int}")]
    public async Task<IActionResult> CreateReturnRequestUser(int assignmentid)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized("User not logged in");
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentUser.Location == null) return Unauthorized("User location not set");

        await _returnService.CreateReturnRequestUser(assignmentid, currentUser.Location.ToString(), currentUser.Id);
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpPost("admin/{assignmentid:int}")]
    public async Task<IActionResult> CreateReturnRequestAdmin(int assignmentid)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized("Admin not logged in");
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Location == null) return Unauthorized("Admin location not set");

        await _returnService.CreateReturnRequestAdmin(assignmentid, currentAdmin.Location.ToString(), currentAdmin.Id);
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetReturnRequest(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized("User not logged in");
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var request = await _returnService.GetReturnRequest(id);
        if (request == null) return NotFound();
        if (request.Location == null) return NotFound("User location not set");
        if (!request.Location.Equals(currentUser?.Location)) return Unauthorized("Permission to see this request denied");
        return Ok(request);
    }

    [Authorize(Role.Admin)]
    [HttpGet]
    public async Task<IActionResult> GetAllReturnRequests()
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized("User not logged in");
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentUser.Location == null) return Unauthorized("User location not set");

        var requests = await _returnService.GetAllReturnRequests();

        var requestsSameLocation = requests.Where(r => r.Location.Equals(currentUser.Location));
        return Ok(requestsSameLocation);
    }

    [Authorize(Role.Admin)]
    [HttpDelete]
    public async Task<IActionResult> DeleteReturnRequest(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized("User not logged in");
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Location == null) return Unauthorized("User location not set");

        await _returnService.DeleteReturnRequest(id, currentAdmin.Location.ToString());
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpPut]
    public async Task<IActionResult> AcceptReturnRequest(int requestid)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized("User not logged in");
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Location == null) return Unauthorized("User location not set");

        await _returnService.AcceptReturnRequest(requestid, currentAdmin.Id, currentAdmin.Location.ToString());
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpGet("pagination")]
    public async Task<IActionResult> GetAllReturnRequestsPagination(string? filterstate = null, DateTime filterreturndate = new DateTime(), string? search = null, string? sort = "asc", string? sortTerm = "assetcode", int page = 1, int pageSize = 10)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized("User not logged in");
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentUser.Location == null) return Unauthorized("User location not set");

        var requests = await _returnService.GetAllReturnRequests();

        var requestsSameLocation = requests.Where(r => r.Location.Equals(currentUser.Location));
        var pagination = _ultilitiesService.GetReturnResults(requestsSameLocation, filterstate, filterreturndate, search, sort, sortTerm, page, pageSize);
        return Ok(pagination);
    }
}
