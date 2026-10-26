/** Icons available in IconSprite.vue (one inline sprite we author; no icon package). */
export const ICON_NAMES = ['info', 'success', 'warning', 'danger', 'close', 'eye', 'eye-off'] as const;

export type IconName = (typeof ICON_NAMES)[number];

export const ICON_ID_PREFIX = 'ca-icon-';
