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

  // Force dataflow computation before exporting
  // This generates REACHING_DEF edges across function boundaries
  run.ossdataflow

  // Export a wider set of nodes for better taint tracking
  val nodesList = (cpg.method.l ++ cpg.call.l ++ cpg.controlStructure.l ++ cpg.methodParameterIn.l ++ cpg.local.l ++ cpg.identifier.l).map { n =>
    val id = n.id().toString
    val lbl = n.label
    
    val filenameAny = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.filename
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => 
        c.method.filename.headOption.getOrElse("")
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => 
        cs.method.filename.headOption.getOrElse("")
      case mp: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn =>
        mp.method.filename.headOption.getOrElse("")
      case l: io.shiftleft.codepropertygraph.generated.nodes.Local =>
        l.method.filename.headOption.getOrElse("")
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        i.method.filename.headOption.getOrElse("")
      case _ => ""
    }
    val filename = filenameAny.toString
    
    val ls = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.lineNumber.getOrElse(-1)
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.lineNumber.getOrElse(-1)
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => cs.lineNumber.getOrElse(-1)
      case mp: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => mp.lineNumber.getOrElse(-1)
      case l: io.shiftleft.codepropertygraph.generated.nodes.Local => l.lineNumber.getOrElse(-1)
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.lineNumber.getOrElse(-1)
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
      case mp: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => mp.name
      case l: io.shiftleft.codepropertygraph.generated.nodes.Local => l.name
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.name
      case _ => ""
    }

    val code = n match {
      case m: io.shiftleft.codepropertygraph.generated.nodes.Method => m.code
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.code
      case cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure => cs.code
      case mp: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => mp.code
      case l: io.shiftleft.codepropertygraph.generated.nodes.Local => l.code
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.code
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

  // Export ALL relevant edges for data-flow tracking
  val edgesList = cpg.graph.allEdges.filter(e => 
    Set("CALL", "CFG", "REACHING_DEF", "REF", "AST", "PARAMETER_LINK", "ARGUMENT", "RECEIVER").contains(e.label)
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
