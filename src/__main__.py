from itertools import product
import math

# I was going to spend the time to draw a cool logo
# here, but ran out of time :(

SIZE = r = 50

# fmt: off

# def main(r: int = SIZE) -> None:
#     d, rmin, rmax = r*2 + 1, -r, r + 1
#     bounds = range(rmin, rmax)
#     grid = [["."]*d for _ in range(d)]
#     for x, y in product(bounds, repeat=2):
#         if abs(math.sqrt(x*x + y*y) - r) < 0.5:
#             grid[x + r][y + r] = "@"
#     for row in grid:
#         print(*row)


# main()
