/**
 * Copyright 2026 Hybrid Mount Developers
 * SPDX-License-Identifier: Apache-2.0
 */

import { createRenderEffect } from "solid-js";
import "./Skeleton.css";

type SkeletonVariant =
  | "hero-label"
  | "hero-title"
  | "hero-caption"
  | "metric"
  | "stats-bar"
  | "info-wide"
  | "info-narrow"
  | "chip-row"
  | "contributor-avatar"
  | "contributor-title"
  | "contributor-body"
  | "module-card"
  | "feature-card"
  | "rule-card";

interface Props {
  variant?: SkeletonVariant;
  width?: string;
  height?: string;
  borderRadius?: string;
  class?: string;
}

export default function Skeleton(props: Props) {
  let rootRef: HTMLDivElement | undefined;

  createRenderEffect(() => {
    const root = rootRef;
    if (!root) return;

    if (props.width) {
      root.style.setProperty("--skeleton-width", props.width);
    } else {
      root.style.removeProperty("--skeleton-width");
    }

    if (props.height) {
      root.style.setProperty("--skeleton-height", props.height);
    } else {
      root.style.removeProperty("--skeleton-height");
    }

    if (props.borderRadius) {
      root.style.setProperty("--skeleton-radius", props.borderRadius);
    } else {
      root.style.removeProperty("--skeleton-radius");
    }
  });

  return (
    <div
      ref={rootRef}
      class={`skeleton ${props.variant ? `skeleton--${props.variant}` : ""} ${
        props.class || ""
      }`.trim()}
    ></div>
  );
}
