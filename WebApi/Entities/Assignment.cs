using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities;

public class Assignment : BaseEntity {
    [Required]
    public int AssetId { get; set; }
    public virtual Asset? Asset { get; set; }
    [Required]
    public int AssignToId { get; set; }
    public virtual User? AssignTo { get; set; }
    [Required]
    public int AssignedById { get; set; }
    public virtual User? AssignedBy { get; set; }
    public DateTime AssignedDate { get; set; }
    [StringLength(500)]
    public string? Note { get; set; }
    public AssignmentState State { get; set; }
    [Required]
    public string? Location { get; set; }
    [Required]
    public bool IsInProgress { get; set; }
    public DateTime CreateAt { get; set; }
    public int CreateBy { get; set; }
    public DateTime? UpdateAt { get; set; }
    public int? UpdateBy { get; set; }
}