namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Assignments;
using WebApi.Models.Users;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class AssignmentsController : ControllerBase
{
    private IAssignmentService _assignmentService;
    private IUserService _userService;
    private readonly IUltilitiesService _ultilitiesService;

    public AssignmentsController(IAssignmentService assignmentService, IUserService userService, IUltilitiesService ultilitiesService)
    {
        _assignmentService = assignmentService;
        _userService = userService;
        _ultilitiesService = ultilitiesService;
    }

    [Authorize(Role.Admin)]
    [HttpPost]
    public async Task<IActionResult> CreateAssignment(AssignmentCreateModel assignment)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Location == null) return Unauthorized(new { message = "Location of admin is not set" });

        await _assignmentService.CreateAssignment(assignment, currentAdmin.Location.ToString(), currentAdmin.Id);
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpPut]
    public async Task<IActionResult> UpdateAssignment(AssignmentUpdateModel assignment)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        if (currentAdmin.Location == null) return Unauthorized(new { message = "Location of admin is not set" });

        await _assignmentService.UpdateAssignment(assignment, currentAdmin.Location.ToString(), currentAdmin.Id);
        return Ok();
    }

    [Authorize(Role.Admin)]
    [HttpGet]
    public async Task<IActionResult> GetAllAssignments()
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var assignments = await _assignmentService.GetAllAssignments();
        var assignmentsSameLocation = assignments.Where(a => a.Location.Equals(currentAdmin?.Location));
        return Ok(assignmentsSameLocation);
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetAssignment(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var assignment = await _assignmentService.GetAssignment(id);
        if (!assignment.Location.Equals(currentUser?.Location)) return Unauthorized(new { message = "Unauthorized" });
        if (currentUser?.Type == Role.Admin || assignment.AssignToId == currentUser?.Id)
            return Ok(assignment);
        return Unauthorized(new { message = "Permission to see this assignment is denied" });

    }

    [Authorize(Role.Admin)]
    [HttpDelete]
    public async Task<IActionResult> DeleteAssignment(int id)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _assignmentService.DeleteAssignment(id, currentAdmin.Location);
        return Ok();
    }

    [HttpPut("{id:int}/{state}")]
    public async Task<IActionResult> UpdateAssignmentStatus(int id, string state) // assignment id and assignment state
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return BadRequest(new { message = "User not found" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        await _assignmentService.UpdateAssignmnetState(id, state, currentUser.Id);
        return Ok();
    }

    [HttpGet("user")]
    public async Task<IActionResult> GetAssignmentsByUser()
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentUser = (User)mwi.User;
        if (currentUser == null) return BadRequest(new { message = "User not found" });
        if (currentUser.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var assignments = await _assignmentService.GetAssignmentsByUser(currentUser.Id);
        return Ok(assignments);
    }

    [Authorize(Role.Admin)]
    [HttpGet("pagination")]
    public async Task<IActionResult> GetAllAssignmentsPagination(string? filterstate = null, DateTime filterassigneddate = new DateTime(), string? search = null, string? sort = "asc", string? sortTerm = "assetcode", int page = 1, int pageSize = 10)
    {
        //check logout
        var mwi = (MiddlewareInfo)HttpContext.Items["UserTokenInfo"];
        var check = await _userService.CheckTokenLoggedout(mwi.Token);
        if (check) return Unauthorized(new { message = "You are already logged out" });

        var currentAdmin = (User)mwi.User;
        if (currentAdmin == null) return Unauthorized(new { message = "You are not logged in" });
        if (currentAdmin.IsDisabled) return BadRequest(new { message = "Your account is disabled" });
        var assignments = await _assignmentService.GetAllAssignments();
        var assignmentsSameLocation = assignments.Where(a => a.Location.Equals(currentAdmin?.Location));
        var pagination = _ultilitiesService.GetAssignmentResults(assignmentsSameLocation, filterstate, filterassigneddate, search, sort, sortTerm, page, pageSize);
        return Ok(pagination);
    }
}