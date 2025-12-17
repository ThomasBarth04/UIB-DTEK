package student;

import java.util.*;

import graph.*;

public class ProblemSolver implements IProblem {

  // O(m*logn)
  public <V, E extends Comparable<E>> LinkedList<Edge<V>> mst(WeightedGraph<V, E> g) {
    LinkedList<Edge<V>> solution = new LinkedList<>();// O(1)

    PriorityQueue<Edge<V>> pq = new PriorityQueue<>(g);// O(1)

    V currentNode = g.getFirstNode();// O(1)

    Edge<V> currentEdge;// O(1)

    Set<V> visited = new HashSet<>();// O(1)
    visited.add(currentNode);// O(1)

    addNewEdgesToQue(pq, g, currentNode, visited);// O(m*logn)
    while (visited.size() < g.verticesCount()) {// O(n * m * logn)
      if (pq.isEmpty()) {// O(1)
        System.out.println("Tree not connected");
        return solution;
      } else {
        currentEdge = pq.poll();// O(logn)
      }

      if (visited.contains(currentEdge.a) && visited.contains(currentEdge.b)) {// O(1)
        continue;// O(1)
      } else {
        solution.add(currentEdge);// O(1)
        currentNode = visited.contains(currentEdge.a) ? currentEdge.b : currentEdge.a;// O(1)
        visited.add(currentNode);// O(1)*
      }
      addNewEdgesToQue(pq, g, currentNode, visited);// O(m*logn)
    }
    return solution;
  }

  // O(m*logn)
  private <V, E extends Comparable<E>> void addNewEdgesToQue(PriorityQueue<Edge<V>> pq, WeightedGraph<V, E> g,
      V currentNode, Set<V> visited) {
    for (Edge<V> adjecentEdge : g.adjacentEdges(currentNode)) {
      if (!visited.contains(adjecentEdge.a) || !visited.contains(adjecentEdge.b)) {
        pq.add(adjecentEdge);
      }
    }
  }

  @Override
  public <V> V lca(Graph<V> g, V root, V u, V v) {// O(n)
    Map<V, V> parentNodes = new HashMap<>();
    Queue<V> q = new LinkedList<>();
    Set<V> visited = new HashSet<>();
    q.add(root);
    while (!q.isEmpty()) {
      V node = q.poll();
      visited.add(node);
      for (V neighbour : g.neighbours(node)) {
        if (!visited.contains(neighbour)) {
          q.add(neighbour);
          parentNodes.put(neighbour, node);
        }
      }
      if (visited.contains(u) && visited.contains(v)) {
        break;
      }
    }
    ArrayList<V> pathV = new ArrayList<>();
    ArrayList<V> pathU = new ArrayList<>();

    V nodeU = u;
    V nodeV = v;

    while (nodeU != root) {
      pathU.add(nodeU);
      nodeU = parentNodes.get(nodeU);
    }
    while (nodeV != root) {
      pathV.add(nodeV);
      nodeV = parentNodes.get(nodeV);
    }

    Collections.reverse(pathU);
    Collections.reverse(pathV);

    if (pathU.isEmpty() || pathV.isEmpty()) {
      return root;
    }
    if (!pathU.get(0).equals(pathV.get(0))) {
      return root;
    }
    if (pathU.size() == 1 || pathV.size() == 1) {
      return pathU.get(0);
    }

    int uIndex = 0;
    int vIndex = 0;

    while (pathV.get(vIndex).equals(pathU.get(uIndex))) {
      uIndex++;
      vIndex++;
      if (pathV.get(vIndex) != pathU.get(uIndex)) {
        return pathU.get(uIndex - 1);
      }
    }
    return root;
  }

  @Override
  public <V> Edge<V> addRedundant(Graph<V> g, V root) {
    Map<V, Integer> childrenCount = countChildrenInMst(g, root);
    Set<V> visited = new HashSet<>();
    visited.add(root);

    V nodeA = root;
    V nodeB = root;
    int maxA = 0;
    int maxB = 0;

    for (V child : g.neighbours(root)) {// O(n)
      int children = childrenCount.get(child);
      if (children > maxA) {
        maxB = maxA;
        nodeB = nodeA;

        maxA = children;
        nodeA = child;
        continue;
      }
      if (children > maxB) {
        maxB = children;
        nodeB = child;
      }
    }

    nodeA = getOptimalNode(childrenCount, nodeA, g, visited);// O(n)
    // edge case: root has degree 1
    if (nodeB != root) {
      nodeB = getOptimalNode(childrenCount, nodeB, g, visited);// O(n)
    }

    return new Edge<>(nodeA, nodeB);
  }

  public <V> Map<V, Integer> countChildrenInMst(Graph<V> g, V root) {
    Map<V, Integer> childrenCount = new HashMap<>();
    Set<V> visited = new HashSet<>();
    dfs(root, g, childrenCount, visited);
    return childrenCount;
  }

  private <V> int dfs(V start, Graph<V> g, Map<V, Integer> childrenCount, Set<V> visited) {
    visited.add(start);
    int numChildren = 0;
    for (V neighbour : g.neighbours(start)) {
      if (!visited.contains(neighbour)) {
        int children = dfs(neighbour, g, childrenCount, visited);
        numChildren += children + 1;
      }
    }
    childrenCount.put(start, numChildren);
    return numChildren;
  }

  private <V> V getOptimalNode(Map<V, Integer> childrenCount, V start, Graph<V> g, Set<V> visited) {
    V currentNode = start;
    visited.add(start);
    while (childrenCount.get(currentNode) != g.degree(currentNode) - 1) {
      int max = 0;
      for (V child : g.neighbours(currentNode)) {
        if (visited.contains(child)) {
          continue;
        }
        if (childrenCount.get(child) > max) {
          max = childrenCount.get(child);
          currentNode = child;
        }
      }
      visited.add(currentNode);
    }

    return currentNode;
  }
}
