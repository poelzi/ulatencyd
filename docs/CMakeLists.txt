FILE(GLOB man1 RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "*.1")

FILE(GLOB man8 RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "*.8")

install(FILES ${man1}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)
install(FILES ${man8}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man8)


FILE(GLOB docfiles RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "wiki/*.md")

MESSAGE(STATUS "Process file: ${docfiles}")

macro(CONVDOC SUFFIX TARGET_FORMAT TARGET_DIR)
  ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}
      COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}
      )
  
  #FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR})
  FOREACH(infileName ${docfiles})
      #MESSAGE(STATUS "Process file: ${infileName}")

      # Generate output file name
      STRING(REPLACE ".md" "${SUFFIX}" outfileName "${infileName}")
      STRING(REPLACE "wiki/" "" outfileName "${outfileName}")
      SET(outfile "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/${outfileName}")
      #MESSAGE(STATUS "Output file: ${outfile}")

      # Generate input file name
      SET(infile "${CMAKE_CURRENT_SOURCE_DIR}/${infileName}")

      # Custom command to do the processing
      ADD_CUSTOM_COMMAND(OUTPUT "${outfile}"
          COMMAND pandoc
          "${infile}" -o "${outfile}" -t ${TARGET_FORMAT}
          DEPENDS "${infile}" "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}"  # depends on the 'processor'
          COMMENT "convent ${infile} => ${outfile}")

      # Finally remember the output file for dependencies
      SET(${TARGET_DIR}Files ${${TARGET_DIR}Files} "${outfile}")
  ENDFOREACH(infileName)
endmacro(CONVDOC)

CONVDOC(.html html html)
CONVDOC("" plain txt)
# Setup a target to drive the conversion
ADD_CUSTOM_TARGET(docs-html DEPENDS ${htmlFiles})
ADD_CUSTOM_TARGET(docs-txt DEPENDS ${txtFiles})


ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/api
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/api
    )
add_custom_target(docs-api
                  doxygen ${CMAKE_SOURCE_DIR}/docs/doxygen.conf
                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/api)

install(DIRECTORY api
        DESTINATION doc/ulatencyd
        OPTIONAL)

install(DIRECTORY html
        DESTINATION doc/ulatencyd
        OPTIONAL)

install(DIRECTORY txt
        DESTINATION doc/ulatencyd
        OPTIONAL)

add_custom_target(docs)
add_dependencies(docs docs-txt docs-html docs-api)


# macro(CONVDOC GLOB SUFFIX TARGET_FORMAT)
#   file(GLOB DOCS RELATIVE wiki ${GLOB})
#   message(${DOCS})
#   file(MAKE_DIRECTORY ${TARGET_FORMAT})
#   foreach(cfile in DOCS)
#     message(string(REPLACE ".md" "${SUFFIX}"))
#     #set(ofile, string(REPLACE ".md" "${SUFFIX}"))
#     #execute_process(pandoc -o ${TARGET_FORMAT}/${ofile} -t {TARGET_FORMAT} -f markdown ${cfile})
#   endforeach(cfile in DOCS)
# endmacro(CONVDOC)
#
#
# add_custom_target(docs-html
#                   COMMAND )