﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using WebApi.Helpers;

#nullable disable

namespace WebApi.Migrations
{
    [DbContext(typeof(DataContext))]
    [Migration("20220426044000_InitialCreate")]
    partial class InitialCreate
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "6.0.3")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder, 1L, 1);

            modelBuilder.Entity("WebApi.Entities.Asset", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<string>("AssetCode")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("AssetName")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("nvarchar(50)");

                    b.Property<int>("CategoryId")
                        .HasColumnType("int");

                    b.Property<DateTime>("CreateAt")
                        .HasColumnType("datetime2");

                    b.Property<int>("CreateBy")
                        .HasColumnType("int");

                    b.Property<DateTime>("InstalledDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Location")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Specification")
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.Property<int>("State")
                        .HasColumnType("int");

                    b.Property<DateTime?>("UpdateAt")
                        .HasColumnType("datetime2");

                    b.Property<int?>("UpdateBy")
                        .HasColumnType("int");

                    b.HasKey("Id");

                    b.HasIndex("CategoryId");

                    b.ToTable("Asset", (string)null);
                });

            modelBuilder.Entity("WebApi.Entities.Assignment", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<int>("AssetId")
                        .HasColumnType("int");

                    b.Property<int>("AssignToId")
                        .HasColumnType("int");

                    b.Property<int>("AssignedById")
                        .HasColumnType("int");

                    b.Property<DateTime>("AssignedDate")
                        .HasColumnType("datetime2");

                    b.Property<DateTime>("CreateAt")
                        .HasColumnType("datetime2");

                    b.Property<int>("CreateBy")
                        .HasColumnType("int");

                    b.Property<bool>("IsInProgress")
                        .HasColumnType("bit");

                    b.Property<string>("Location")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Note")
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.Property<int>("State")
                        .HasColumnType("int");

                    b.Property<DateTime?>("UpdateAt")
                        .HasColumnType("datetime2");

                    b.Property<int?>("UpdateBy")
                        .HasColumnType("int");

                    b.HasKey("Id");

                    b.HasIndex("AssetId");

                    b.HasIndex("AssignToId");

                    b.HasIndex("AssignedById");

                    b.ToTable("Assignment", (string)null);
                });

            modelBuilder.Entity("WebApi.Entities.Category", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<string>("CategoryName")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<DateTime>("CreateAt")
                        .HasColumnType("datetime2");

                    b.Property<int>("CreateBy")
                        .HasColumnType("int");

                    b.Property<string>("Prefix")
                        .IsRequired()
                        .HasMaxLength(5)
                        .HasColumnType("nvarchar(5)");

                    b.Property<DateTime?>("UpdateAt")
                        .HasColumnType("datetime2");

                    b.Property<int?>("UpdateBy")
                        .HasColumnType("int");

                    b.HasKey("Id");

                    b.ToTable("Category", (string)null);

                    b.HasData(
                        new
                        {
                            Id = 1,
                            CategoryName = "Laptop",
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            Prefix = "LA"
                        },
                        new
                        {
                            Id = 2,
                            CategoryName = "Desktop",
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            Prefix = "DE"
                        },
                        new
                        {
                            Id = 3,
                            CategoryName = "Printer",
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            Prefix = "PR"
                        },
                        new
                        {
                            Id = 4,
                            CategoryName = "Scanner",
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            Prefix = "SC"
                        },
                        new
                        {
                            Id = 5,
                            CategoryName = "Network",
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            Prefix = "NE"
                        });
                });

            modelBuilder.Entity("WebApi.Entities.ReturnRequest", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<int?>("AcceptedById")
                        .HasColumnType("int");

                    b.Property<int>("AssetId")
                        .HasColumnType("int");

                    b.Property<DateTime?>("AssignedDate")
                        .HasColumnType("datetime2");

                    b.Property<DateTime>("CreateAt")
                        .HasColumnType("datetime2");

                    b.Property<int>("CreateBy")
                        .HasColumnType("int");

                    b.Property<string>("Location")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("RequestedById")
                        .HasColumnType("int");

                    b.Property<DateTime?>("ReturnedDate")
                        .HasColumnType("datetime2");

                    b.Property<int>("State")
                        .HasColumnType("int");

                    b.Property<DateTime?>("UpdateAt")
                        .HasColumnType("datetime2");

                    b.Property<int?>("UpdateBy")
                        .HasColumnType("int");

                    b.HasKey("Id");

                    b.HasIndex("AcceptedById");

                    b.HasIndex("AssetId");

                    b.HasIndex("RequestedById");

                    b.ToTable("ReturnRequest", (string)null);
                });

            modelBuilder.Entity("WebApi.Entities.TokenLogout", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<DateTime>("ExpirationDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Token")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("TokenLogout", (string)null);
                });

            modelBuilder.Entity("WebApi.Entities.User", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<DateTime>("CreateAt")
                        .HasColumnType("datetime2");

                    b.Property<int>("CreateBy")
                        .HasColumnType("int");

                    b.Property<DateTime>("DoB")
                        .HasColumnType("datetime2");

                    b.Property<string>("Firstname")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Gender")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<bool>("IsDisabled")
                        .HasColumnType("bit");

                    b.Property<bool>("IsFirstLogin")
                        .HasColumnType("bit");

                    b.Property<DateTime>("JoinDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Lastname")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Location")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("PasswordHash")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("StaffCode")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("Type")
                        .HasColumnType("int");

                    b.Property<DateTime?>("UpdateAt")
                        .HasColumnType("datetime2");

                    b.Property<int?>("UpdateBy")
                        .HasColumnType("int");

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("User", (string)null);

                    b.HasData(
                        new
                        {
                            Id = 1,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1991, 12, 15, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Ed",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 9, 8, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Pendlebery",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$lR4IKFjrbwrqXdM/Em9MUervBNTPx1En85Kso44fjvJel2KGUzdIW",
                            StaffCode = "SD0001",
                            Type = 0,
                            Username = "edp"
                        },
                        new
                        {
                            Id = 2,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1992, 9, 7, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Courtney",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 8, 6, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "O'Loinn",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$dp.sMvR8/cfodlqLB2NdzOYmIqOzFPxJjoEAG0H4Hv0OgPkdNFHuO",
                            StaffCode = "SD0002",
                            Type = 1,
                            Username = "courtneyo"
                        },
                        new
                        {
                            Id = 3,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1991, 5, 5, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Eudora",
                            Gender = "Female",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 5, 23, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Renahan",
                            Location = "Hanoi",
                            PasswordHash = "$2a$11$gJ.qk2chdnV5BRETDEuUBuPW.yZ1IUdd.rOFkk4CkIeaOeKOGE/yi",
                            StaffCode = "SD0003",
                            Type = 0,
                            Username = "eudorar"
                        },
                        new
                        {
                            Id = 4,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1991, 3, 10, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Bevin",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 12, 9, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Hugueville",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$90Hm3y/GIdsxb9HiqRlN4O/l7G4jRXc7JnfdyeuzixL5fewxcWciS",
                            StaffCode = "SD0004",
                            Type = 1,
                            Username = "bevinh"
                        },
                        new
                        {
                            Id = 5,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1998, 6, 21, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Andrew",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 3, 31, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Broadis",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$1WH6TFWb3g8pOotNVohs2.727OAax2aPpsbHNb9CDozBmB/BQx8S.",
                            StaffCode = "SD0005",
                            Type = 1,
                            Username = "andrewb"
                        },
                        new
                        {
                            Id = 6,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1994, 12, 21, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Tades",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2022, 2, 18, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Zecchi",
                            Location = "Hanoi",
                            PasswordHash = "$2a$11$t.xCSseyLryXo71IFT/.QOTZGs2uCoGEnL37PnJPaCP3bpOcppqWy",
                            StaffCode = "SD0006",
                            Type = 1,
                            Username = "tadesz"
                        },
                        new
                        {
                            Id = 7,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1999, 10, 25, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Vernor",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2022, 1, 4, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Huson",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$tl1voexE4G6luCi.zz7wFOcuGMEuIxDuG9H7JgsdpkaNi0E1ISbkO",
                            StaffCode = "SD0007",
                            Type = 1,
                            Username = "vernorh"
                        },
                        new
                        {
                            Id = 8,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1990, 11, 16, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Rufe",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2022, 1, 17, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Yole",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$02yewSMpdY3ncliExP2WmOxH1.8Aul5igpqtufS7YlI20a5bpOnDW",
                            StaffCode = "SD0008",
                            Type = 1,
                            Username = "rufey"
                        },
                        new
                        {
                            Id = 9,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1994, 3, 29, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Orton",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 11, 29, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Woodyear",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$6d4gGEsnkGLX0eTxre7He.baiVnkHQMd7hxAUmwhTjS54xbakSRAy",
                            StaffCode = "SD0009",
                            Type = 1,
                            Username = "ortonw"
                        },
                        new
                        {
                            Id = 10,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(2000, 1, 17, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Peyter",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 5, 18, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Carmichael",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$u5ihAkpEc7O7h3s9vjgBs.G1KQhggz6hn2OmWGDcryk6WHejUKrmi",
                            StaffCode = "SD0010",
                            Type = 1,
                            Username = "peyterc"
                        },
                        new
                        {
                            Id = 11,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1995, 7, 17, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Kathy",
                            Gender = "Female",
                            IsDisabled = false,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 7, 14, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Pitchers",
                            Location = "Hanoi",
                            PasswordHash = "$2a$11$Vn/sanNjXFl2ODyLrWX9PuEWWfTmz6m4g.6c8MiK1Nf7y9yaqF5Xi",
                            StaffCode = "SD0011",
                            Type = 1,
                            Username = "kathyp"
                        },
                        new
                        {
                            Id = 12,
                            CreateAt = new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            CreateBy = 0,
                            DoB = new DateTime(1991, 7, 20, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Beau",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 8, 11, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Thorndycraft",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$E/INVeGGBOmOcbG4gBx9KOo8pNAod5ny8KbQT0kmGCHZRM2hB6h0u",
                            StaffCode = "SD0012",
                            Type = 1,
                            Username = "beaut"
                        });
                });

            modelBuilder.Entity("WebApi.Entities.Asset", b =>
                {
                    b.HasOne("WebApi.Entities.Category", "Category")
                        .WithMany("Assets")
                        .HasForeignKey("CategoryId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Category");
                });

            modelBuilder.Entity("WebApi.Entities.Assignment", b =>
                {
                    b.HasOne("WebApi.Entities.Asset", "Asset")
                        .WithMany("Assignments")
                        .HasForeignKey("AssetId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("WebApi.Entities.User", "AssignTo")
                        .WithMany("AssignTos")
                        .HasForeignKey("AssignToId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("WebApi.Entities.User", "AssignedBy")
                        .WithMany("AssignBys")
                        .HasForeignKey("AssignedById")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Asset");

                    b.Navigation("AssignTo");

                    b.Navigation("AssignedBy");
                });

            modelBuilder.Entity("WebApi.Entities.ReturnRequest", b =>
                {
                    b.HasOne("WebApi.Entities.User", "AcceptedBy")
                        .WithMany("AcceptBys")
                        .HasForeignKey("AcceptedById")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("WebApi.Entities.Asset", "Asset")
                        .WithMany("ReturnRequests")
                        .HasForeignKey("AssetId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("WebApi.Entities.User", "RequestedBy")
                        .WithMany("ReturnBys")
                        .HasForeignKey("RequestedById")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("AcceptedBy");

                    b.Navigation("Asset");

                    b.Navigation("RequestedBy");
                });

            modelBuilder.Entity("WebApi.Entities.Asset", b =>
                {
                    b.Navigation("Assignments");

                    b.Navigation("ReturnRequests");
                });

            modelBuilder.Entity("WebApi.Entities.Category", b =>
                {
                    b.Navigation("Assets");
                });

            modelBuilder.Entity("WebApi.Entities.User", b =>
                {
                    b.Navigation("AcceptBys");

                    b.Navigation("AssignBys");

                    b.Navigation("AssignTos");

                    b.Navigation("ReturnBys");
                });
#pragma warning restore 612, 618
        }
    }
}