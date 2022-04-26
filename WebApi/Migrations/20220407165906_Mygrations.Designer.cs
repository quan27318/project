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
    [Migration("20220407165906_Mygrations")]
    partial class Mygrations
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
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("AssetName")
                        .HasMaxLength(50)
                        .HasColumnType("nvarchar(50)");

                    b.Property<int>("CategoryId")
                        .HasColumnType("int");

                    b.Property<DateTime>("InstalledDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Location")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Specification")
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.Property<int>("State")
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

                    b.Property<bool>("IsInProgress")
                        .HasColumnType("bit");

                    b.Property<string>("Location")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Note")
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("State")
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

                    b.Property<string>("Prefix")
                        .IsRequired()
                        .HasMaxLength(5)
                        .HasColumnType("nvarchar(5)");

                    b.HasKey("Id");

                    b.ToTable("Category", (string)null);

                    b.HasData(
                        new
                        {
                            Id = 1,
                            CategoryName = "Laptop",
                            Prefix = "LA"
                        },
                        new
                        {
                            Id = 2,
                            CategoryName = "Desktop",
                            Prefix = "DE"
                        },
                        new
                        {
                            Id = 3,
                            CategoryName = "Printer",
                            Prefix = "PR"
                        },
                        new
                        {
                            Id = 4,
                            CategoryName = "Scanner",
                            Prefix = "SC"
                        },
                        new
                        {
                            Id = 5,
                            CategoryName = "Network",
                            Prefix = "NE"
                        });
                });

            modelBuilder.Entity("WebApi.Entities.ReturnRequest", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<int>("AcceptedById")
                        .HasColumnType("int");

                    b.Property<int>("AssetId")
                        .HasColumnType("int");

                    b.Property<string>("Location")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("RequestedById")
                        .HasColumnType("int");

                    b.Property<DateTime>("ReturnedDate")
                        .HasColumnType("datetime2");

                    b.Property<int>("State")
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

                    b.Property<DateTime>("DoB")
                        .HasColumnType("datetime2");

                    b.Property<string>("Firstname")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Gender")
                        .HasColumnType("nvarchar(max)");

                    b.Property<bool>("IsDisabled")
                        .HasColumnType("bit");

                    b.Property<bool>("IsFirstLogin")
                        .HasColumnType("bit");

                    b.Property<DateTime>("JoinDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Lastname")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Location")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("PasswordHash")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("StaffCode")
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("Type")
                        .HasColumnType("int");

                    b.Property<string>("Username")
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("User", (string)null);

                    b.HasData(
                        new
                        {
                            Id = 1,
                            DoB = new DateTime(1991, 12, 15, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Ed",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 9, 8, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Pendlebery",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$UH5.MHAObnB3WbbHlg30leP5xAHrv141zBDETeQTiOTHfKOkidFRm",
                            StaffCode = "SD0001",
                            Type = 0,
                            Username = "edp"
                        },
                        new
                        {
                            Id = 2,
                            DoB = new DateTime(1992, 9, 7, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Courtney",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 8, 6, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "O'Loinn",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$FqK.qEmblwYC9Y36zeNfLu7VDIxgBdvvhUWBeVIkX9tRBPw/zjz4G",
                            StaffCode = "SD0002",
                            Type = 1,
                            Username = "courtneyo"
                        },
                        new
                        {
                            Id = 3,
                            DoB = new DateTime(1991, 5, 5, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Eudora",
                            Gender = "Female",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 5, 23, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Renahan",
                            Location = "Hanoi",
                            PasswordHash = "$2a$11$UC2z5FkocRovMTIiAoZbuutjF5oEZr7hxyXs87pPQdf2rrAS9Qncy",
                            StaffCode = "SD0003",
                            Type = 0,
                            Username = "eudorar"
                        },
                        new
                        {
                            Id = 4,
                            DoB = new DateTime(1991, 3, 10, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Bevin",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 12, 9, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Hugueville",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$Z7LNq0lQMgpvWQk.puAGHOALQVaVx.6wXo30h/ic1t6OFXFdcpr5a",
                            StaffCode = "SD0004",
                            Type = 1,
                            Username = "bevinh"
                        },
                        new
                        {
                            Id = 5,
                            DoB = new DateTime(1998, 6, 21, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Andrew",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 3, 31, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Broadis",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$1cbjCNrXEtyR1RbHEk9bge/vzse/OjTNKgdT4MOdvfqcwTRRrg922",
                            StaffCode = "SD0005",
                            Type = 1,
                            Username = "andrewb"
                        },
                        new
                        {
                            Id = 6,
                            DoB = new DateTime(1994, 12, 21, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Tades",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2022, 2, 18, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Zecchi",
                            Location = "Hanoi",
                            PasswordHash = "$2a$11$NE2gn5tsDJK1l1BO3j.WOuA51YKPYY3eirUR6mDlfLNMzxgBBX5WG",
                            StaffCode = "SD0006",
                            Type = 1,
                            Username = "tadesz"
                        },
                        new
                        {
                            Id = 7,
                            DoB = new DateTime(1999, 10, 25, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Vernor",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2022, 1, 4, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Huson",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$/fmulqSZdtBDKuqolEOCOO80.hL7rzcFs6hWCjyfYO9HntJ.0oBla",
                            StaffCode = "SD0007",
                            Type = 1,
                            Username = "vernorh"
                        },
                        new
                        {
                            Id = 8,
                            DoB = new DateTime(1990, 11, 16, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Rufe",
                            Gender = "Male",
                            IsDisabled = false,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2022, 1, 17, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Yole",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$rfVIfRNWfSdDknBbmy8g9.0D0b/laHau0t3gLfk5Kz3gpI2bawHvC",
                            StaffCode = "SD0008",
                            Type = 1,
                            Username = "rufey"
                        },
                        new
                        {
                            Id = 9,
                            DoB = new DateTime(1994, 3, 29, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Orton",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 11, 29, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Woodyear",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$rnkhQCFXRofLYu8doxE4ne3iWeKH8YO7cFBYM1WDE3CfXb1aGVieW",
                            StaffCode = "SD0009",
                            Type = 1,
                            Username = "ortonw"
                        },
                        new
                        {
                            Id = 10,
                            DoB = new DateTime(2000, 1, 17, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Peyter",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = false,
                            JoinDate = new DateTime(2021, 5, 18, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Carmichael",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$WtnVFcJSWZqdFEZVqwFPBeeJf49EdHVmZ0lsnjgj8CaEGf4wgDEfa",
                            StaffCode = "SD0010",
                            Type = 1,
                            Username = "peyterc"
                        },
                        new
                        {
                            Id = 11,
                            DoB = new DateTime(1995, 7, 17, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Kathy",
                            Gender = "Female",
                            IsDisabled = false,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 7, 14, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Pitchers",
                            Location = "Hanoi",
                            PasswordHash = "$2a$11$Jbwza6rsxUzIB.lvwTfC8OeWWZGQZH9v3LhbJOk0CzoURNvGpBaES",
                            StaffCode = "SD0011",
                            Type = 1,
                            Username = "kathyp"
                        },
                        new
                        {
                            Id = 12,
                            DoB = new DateTime(1991, 7, 20, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Firstname = "Beau",
                            Gender = "Male",
                            IsDisabled = true,
                            IsFirstLogin = true,
                            JoinDate = new DateTime(2021, 8, 11, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Lastname = "Thorndycraft",
                            Location = "Hochiminh",
                            PasswordHash = "$2a$11$h0wTzzoJDxtDSjJ/1pUYN.2o/GLdFKZMU.uWILsSgWOIBER1POHdy",
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
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

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
