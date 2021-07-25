from typing import List, Tuple
import ida_graph
import ida_gdl

def bounding_box(points: List[Tuple[int, int]]):
    x_coordinates, y_coordinates = zip(*points)

    return [(min(x_coordinates), min(y_coordinates)), (max(x_coordinates), max(y_coordinates))]

def graph_size(graph: ida_graph.mutable_graph_t) -> Tuple[int, int]:
    num_nodes = graph.size()
    points = []
    for i in range(num_nodes):
        rect: ida_graph.rect_t = graph.nrect(i)
        topl = rect.topleft()
        points.append((topl.x, topl.y))
        botr = rect.bottomright()
        points.append((botr.x, botr.y))

        for edgei in range(graph.nsucc(i)):
            succ = graph.succ(i, edgei)
            edge = ida_graph.edge_t(i, succ)
            ei = graph.get_edge(edge)
            edge_points: ida_graph.pointseq_t = ei.layout
            for epi in range(edge_points.size()):
                ep = edge_points.at(epi)
                points.append((ep.x, ep.y))
    bb = bounding_box(points)
    l, t = bb[0]
    r, b = bb[1]
    return (r - l, b - t)