class ChainAnalyzer:

    def find_paths(self, graph, max_depth=3):
        paths = []

        for start in graph:
            self._dfs(graph, start, [], paths, max_depth)

        return paths

    def _dfs(self, graph, current, path, paths, depth):
        if depth == 0:
            return

        path = path + [current]

        if not graph[current]["edges"]:
            if len(path) > 1:
                paths.append(path)
            return

        for edge in graph[current]["edges"]:
            self._dfs(graph, edge["to"], path, paths, depth - 1)