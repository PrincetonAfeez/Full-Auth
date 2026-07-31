"""Django management command: bootstrap genesis."""
import getpass

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from accounts.models import EmailAddress
from security_policies.services import get_policy


class Command(BaseCommand):
    help = "Provision the first platform admin and global default security policy idempotently."

    def add_arguments(self, parser):
        parser.add_argument("--username")
        parser.add_argument("--email")
        parser.add_argument("--password")
        parser.add_argument(
            "--force",
            action="store_true",
            help="Allow updating an existing genesis admin (password/email/privileges).",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()
        get_policy()
        username = options["username"] or input("Admin username: ")
        email = options["email"] or input("Admin email: ")
        password = options["password"] or getpass.getpass("Admin password: ")
        if not password:
            raise CommandError("Password is required")
        existing = User.objects.filter(username=username).first()
        if existing and existing.is_superuser and not options["force"] and not options.get("password") and not options.get("email"):
            self.stdout.write(self.style.WARNING(f"Genesis admin already exists: {username} (use --force to modify)"))
            self.stdout.write(self.style.SUCCESS("Global security policy is present."))
            return
        if existing and not existing.is_superuser and not options["force"]:
            raise CommandError(
                f"User {username} already exists and is not a platform admin. "
                "Refusing to elevate without --force."
            )
        verified_at = timezone.now()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email.lower(),
                "is_staff": True,
                "is_superuser": True,
                "status": User.Status.ACTIVE,
                "force_strong_mfa": True,
                "email_verified_at": verified_at,
            },
        )
        if created:
            user.set_password(password)
            user.save(update_fields=["password"])
            EmailAddress.objects.get_or_create(
                user=user,
                email=user.email.lower(),
                defaults={"is_primary": True, "verified_at": verified_at},
            )
            self.stdout.write(self.style.SUCCESS(f"Created genesis platform admin: {username}"))
        else:
            changed = []
            if options.get("password"):
                user.set_password(options["password"])
                changed.append("password")
            elif options["force"]:
                user.set_password(password)
                changed.append("password")
            if options.get("email") and user.email.lower() != options["email"].lower():
                new_email = options["email"].lower()
                user.email = new_email
                changed.append("email")
                primary = EmailAddress.objects.filter(user=user, is_primary=True).first()
                if primary:
                    primary.email = new_email
                    primary.save(update_fields=["email"])
                else:
                    EmailAddress.objects.create(user=user, email=new_email, is_primary=True, verified_at=verified_at)
            if not user.email_verified_at:
                user.email_verified_at = verified_at
                changed.append("email_verified_at")
            if not user.is_staff or not user.is_superuser:
                user.is_staff = True
                user.is_superuser = True
                changed.extend(["is_staff", "is_superuser"])
            if not user.force_strong_mfa:
                user.force_strong_mfa = True
                changed.append("force_strong_mfa")
            if changed:
                user.save(update_fields=changed)
            self.stdout.write(self.style.WARNING(f"Genesis admin already exists: {username}"))
        self.stdout.write(self.style.SUCCESS("Global security policy is present."))
