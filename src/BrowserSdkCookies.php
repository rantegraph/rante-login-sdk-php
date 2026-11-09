<?php

declare(strict_types=1);

namespace Rante\Login;

/** The cookies the Rante Login browser SDK writes with serverSide: true (SameSite=Lax, 10 minutes, Path=/). */
final class BrowserSdkCookies
{
    public const CODE_VERIFIER = 'rante_login_pkce';
    public const STATE = 'rante_login_state';
    public const NONCE = 'rante_login_nonce';
    /** All three, for clearing them once read: each sign-in uses them once. */
    public const ALL = [self::CODE_VERIFIER, self::STATE, self::NONCE];
}
