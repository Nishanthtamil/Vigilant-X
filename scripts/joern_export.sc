@main def exec(repoPath: String, outputPath: String, files: String = "") = {
  if (files != null && files.nonEmpty) {
    files.split(",").filter(_.nonEmpty).foreach(f => importCode(f))
  } else {
    importCode(repoPath)
  }

  def escape(s: String): String = {
    if (s == null) ""
    else s.replace("\\", "\\\\")
          .replace("\"", "\\\"")
          .replace("\n", "\\n")
          .replace("\r", "\\r")
          .replace("\t", "\\t")
  }

  // Export Methods, Calls, and ControlStructures for full PDG support
  val nodesList = (cpg.method.l ++ cpg.call.l ++ cpg.controlStructure.l).map { n =>
    val id = n.id().toString
    val lbl = n.label // Property, not a method call
    
    val filenameAny = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.filename
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => 
        c.method.filename.headOption.getOrElse("")
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => 
        cs.method.filename.headOption.getOrElse("")
      case _ => ""
    }
    val filename = filenameAny.toString
    
    val ls = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.lineNumber.getOrElse(-1)
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.lineNumber.getOrElse(-1)
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => cs.lineNumber.getOrElse(-1)
      case _ => -1
    }

    val le = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.lineNumberEnd.getOrElse(ls)
      case _ => ls
    }

    val name = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.name
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => cs.controlStructureType
      case _ => ""
    }

    val code = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.code
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.code
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => cs.code
      case _ => ""
    }

    "{" +
      "\"node_id\":\"" + id + "\"," +
      "\"file_path\":\"" + escape(filename) + "\"," +
      "\"function_name\":\"" + escape(name) + "\"," +
      "\"line_start\":" + ls + "," +
      "\"line_end\":" + le + "," +
      "\"node_type\":\"" + escape(lbl) + "\"," +
      "\"code\":\"" + escape(code) + "\"" +
    "}"
  }

  // Export CALL, CFG, and REACHING_DEF (PDG) edges
  // In Joern 4.0.x (flatgraph), we use .allEdges to iterate
  val edgesList = cpg.graph.allEdges.filter(e => 
    Set("CALL", "CFG", "REACHING_DEF", "REF").contains(e.label)
  ).map { e =>
    "{" +
      "\"src\":\"" + e.src.id().toString + "\"," +
      "\"dst\":\"" + e.dst.id().toString + "\"," +
      "\"type\":\"" + escape(e.label) + "\"" +
    "}"
  }.toList

  val json = "{\"nodes\":[" + nodesList.mkString(",") + "],\"edges\":[" + edgesList.mkString(",") + "]}"

  os.write(os.Path(outputPath), json)
}
