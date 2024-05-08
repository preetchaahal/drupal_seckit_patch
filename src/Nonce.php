<?php

declare(strict_types=1);

namespace Drupal\seckit;

use Drupal\Component\Utility\Crypt;
use Drupal\Core\Security\TrustedCallbackInterface;

/**
 * Defines a class for a nonce static.
 */
final class Nonce implements TrustedCallbackInterface {

  /**
   * Nonce for current request.
   *
   * @var string|null
   */
  private static $nonce = NULL;

  /**
   * Checks if has nonce.
   */
  public static function hasNonce(): bool {
    return self::$nonce !== NULL;
  }

  /**
   * Gets the curent nonce.
   */
  public static function getNonce(): string {
    if (!self::hasNonce()) {
      self::$nonce = Crypt::randomBytesBase64(24);
    }
    return self::$nonce;
  }

  /**
   * Gets a placeholder for the nonce.
   */
  public static function getPlaceholder(): string {
    return sprintf('nonce_%s', Crypt::hashBase64(__METHOD__));
  }

  /**
   * Renders placeholder.
   */
  public static function replacePlaceholder(): array {
    return [
      '#markup' => self::getNonce(),
    ];
  }

  /**
   * Adds nonce attributes to an element.
   *
   * @param array $element
   *   Render element.
   *
   * @return array
   *   Render element.
   */
  public static function addNonceAttribute(array $element): array {
    if (($element['#tag'] ?? FALSE) !== 'script' || isset($element['#attributes']['src'])) {
      return $element;
    }
    $placeholder = self::getPlaceholder();
    $element['#attached']['placeholders'][$placeholder] = [
      '#lazy_builder' => [[self::class, 'replacePlaceholder'], []],
    ];
    $element['#attributes']['nonce'] = $placeholder;
    return $element;
  }

  /**
   * {@inheritdoc}
   */
  public static function trustedCallbacks(): array {
    return ['replacePlaceholder', 'addNonceAttribute'];
  }

}
