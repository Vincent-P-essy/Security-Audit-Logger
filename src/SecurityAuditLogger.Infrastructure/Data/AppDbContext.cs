using Microsoft.EntityFrameworkCore;
using SecurityAuditLogger.Core.Entities;

namespace SecurityAuditLogger.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Alert> Alerts => Set<Alert>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AuditEvent>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Timestamp);
            e.HasIndex(x => x.Username);
            e.HasIndex(x => x.IpAddress);
            e.HasIndex(x => new { x.Username, x.EventType, x.Timestamp });
            e.Property(x => x.Username).HasMaxLength(256).IsRequired();
            e.Property(x => x.IpAddress).HasMaxLength(45).IsRequired();
            e.Property(x => x.Endpoint).HasMaxLength(512).IsRequired();
            e.Property(x => x.HttpMethod).HasMaxLength(10).IsRequired();
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.Property(x => x.Details).HasMaxLength(2000);
            e.Property(x => x.AnomalyReason).HasMaxLength(1000);
        });

        modelBuilder.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Username).IsUnique();
            e.Property(x => x.Username).HasMaxLength(256).IsRequired();
            e.Property(x => x.PasswordHash).IsRequired();
            e.Property(x => x.Role).HasMaxLength(50).IsRequired();
        });

        modelBuilder.Entity<Alert>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TriggeredAt);
            e.HasIndex(x => x.IsAcknowledged);
            e.Property(x => x.Title).HasMaxLength(256).IsRequired();
            e.Property(x => x.Description).HasMaxLength(2000).IsRequired();
            e.Property(x => x.AffectedUsername).HasMaxLength(256).IsRequired();
            e.Property(x => x.AffectedIpAddress).HasMaxLength(45).IsRequired();
        });

        base.OnModelCreating(modelBuilder);
    }
}
