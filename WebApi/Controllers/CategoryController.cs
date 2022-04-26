namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Assets;
using WebApi.Models.Categories;
using WebApi.Models.Users;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class CategoryController : ControllerBase
{
    private IUserService _userService;

    private IGenericService<CategoryModel> _categoryService;

    public CategoryController(IUserService userService, IGenericService<CategoryModel> categoryService)
    {
        _userService = userService;
        _categoryService = categoryService;
    }
    [Authorize(Role.Admin)]
    [HttpGet]
    public async Task<IActionResult> GetCategories()
    {
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        return Ok(await _categoryService.GetAllAsync());
    }

    [Authorize(Role.Admin)]
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetCategory(int id)
    {
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        return Ok(await _categoryService.GetByIdAsync(id));
    }

    [Authorize(Role.Admin)]
    [HttpPost]
    public async Task<IActionResult> CreateCategory(CategoryModel model)
    {
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (ModelState.IsValid)
        {
            await _categoryService.CreateAsync(model, currentAdmin.Id);
            return Ok("success");
        }
        return BadRequest(model);
    }

    [Authorize(Role.Admin)]
    [HttpDelete]
    public async Task<IActionResult> DeleteCategory(int id){
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _categoryService.DeleteAsync(id);
        return Ok("success");
    }
}