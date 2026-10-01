"""Squarified treemap layout (Bruls, Huizing, van Wijk)."""


def squarify(sizes, x, y, w, h):
    """Lay out `sizes` (largest first, all > 0) inside the rectangle; returns one (x, y, w, h) per size."""
    total = float(sum(sizes))
    if total <= 0 or w <= 0 or h <= 0:
        return []
    areas = [s * w * h / total for s in sizes]
    rects = []

    def worst(row, side):
        s = sum(row)
        return max(max(side * side * a / (s * s), s * s / (side * side * a)) for a in row)

    i = 0
    while i < len(areas):
        side = min(w, h)
        row, j = [areas[i]], i + 1
        while j < len(areas) and worst(row + [areas[j]], side) <= worst(row, side):
            row.append(areas[j])
            j += 1
        s = sum(row)
        if w >= h:                          # the row becomes a column on the left
            col_w = s / h
            cy = y
            for a in row:
                rects.append((x, cy, col_w, a / col_w))
                cy += a / col_w
            x += col_w
            w -= col_w
        else:                               # the row runs along the top
            row_h = s / w
            cx = x
            for a in row:
                rects.append((cx, y, a / row_h, row_h))
                cx += a / row_h
            y += row_h
            h -= row_h
        i = j
    return rects
