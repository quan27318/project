namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Assets;
using WebApi.Models.Users;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class AssetsController : ControllerBase
{
    private IAssetService _assetService;
    private IUserService _userService;
    private readonly IUltilitiesService _ultilitiesService;

    public AssetsController(IAssetService assetService, IUserService userService, IUltilitiesService ultilitiesService)
    {
        _assetService = assetService;
        _userService = userService;
        _ultilitiesService = ultilitiesService;
    }

    [Authorize(Role.Admin)]
    [HttpPost]
    public async Task<IActionResult> CreateAsset(AssetCreateModel asset)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Location == null) return NotFound(new { message = "Location of admin is not set" });

        await _assetService.CreateAsset(asset, currentAdmin.Location.ToString(), currentAdmin.Id);
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpGet]
    public async Task<IActionResult> GetAllAssets()
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var assets = await _assetService.GetAllAssets();
        var assetsSameLocation = assets.Where(a => a.Location.Equals(currentAdmin.Location));
        return Ok(assetsSameLocation);
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetAsset(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var asset = await _assetService.GetAsset(id);
        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        //var assignToId = asset.Assignments?.FirstOrDefault(a => a.AssetId == id)?.AssignToId;
        if (asset.Location.Equals(((User)mwi.User).Location))
            return Ok(asset);
        else
            return Unauthorized(new { message = "Permission are not allowed" });
    }

    [Authorize(Role.Admin)]
    [HttpPut]
    public async Task<IActionResult> UpdateAsset(AssetUpdateModel asset)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _assetService.UpdateAsset(asset, currentAdmin.Location.ToString());
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpDelete]
    public async Task<IActionResult> DeleteAsset(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _assetService.DeleteAsset(id, currentAdmin.Location.ToString());
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpGet("pagination")]
    public async Task<IActionResult> GetAllAssetsPagination(string? filterstate = null, string? filtercategory = null, string? search = null, string? sort = "asc", string? sortTerm = "assetcode", int page = 1, int pageSize = 10)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var assets = await _assetService.GetAllAssets();
        var assetsSameLocation = assets.Where(a => a.Location.Equals(currentAdmin?.Location));
        var pagination = _ultilitiesService.GetAssetResults(assetsSameLocation, filterstate, filtercategory, search, sort, sortTerm, page, pageSize);
        return Ok(pagination);
    }
}