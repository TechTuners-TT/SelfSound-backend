from fastapi import APIRouter
from routes.authorization.google_auth_router import router as auth_router
from routes.posts import post_router
from routes import tags_router
from routes.profile_routes import profile_router
from routes import listeners_router
from routes.authorization import default_auth_router
from routes import blocking_router
from routes.guest import guest_router
from routes import feed_router
from routes.profile_routes import search_profile_router
from routes import reports_router
from routes.notifications_router import router as notifications_router
from routes.admin import router as admin_router

router = APIRouter()

router.include_router(auth_router, prefix="/auth", tags=["Auth"])
router.include_router(post_router.router)
router.include_router(tags_router.router)
router.include_router(listeners_router.router)
router.include_router(profile_router.router)
router.include_router(blocking_router.router)
router.include_router(default_auth_router.router)
router.include_router(guest_router.guest_router)
router.include_router(feed_router.feed_router)
router.include_router(search_profile_router.router)

router.include_router(post_router.router)

router.include_router(auth_router)

router.include_router(notifications_router)

router.include_router(reports_router.router)

router.include_router(admin_router)


