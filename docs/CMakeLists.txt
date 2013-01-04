####################################
##         Manual pages           ##

FILE(GLOB man1 RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "*.1")

FILE(GLOB man8 RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "*.8")

install(FILES ${man1}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)
install(FILES ${man8}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man8)

####################################
## Convert wiki pages to TXT/HTML ##

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

ADD_CUSTOM_TARGET(docs-html DEPENDS ${htmlFiles})
ADD_CUSTOM_TARGET(docs-txt DEPENDS ${txtFiles})

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
        DESTINATION ${CMAKE_INSTALL_PREFIX}/doc/ulatencyd
        OPTIONAL)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/txt
        DESTINATION ${CMAKE_INSTALL_PREFIX}/doc/ulatencyd
        OPTIONAL)


####################################
##   API Doxygen documentation    ##

# Doxygen outputs relative to directory where it was started, create doxygen.conf
# from template where INPUT directories are preprended with ${CMAKE_SOURCE_DIR}
configure_file(doxygen.conf.tmpl ${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf @ONLY)
ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/api
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/api
    )
add_custom_target(docs-api
                  doxygen ${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf
                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/api)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/api
        DESTINATION ${CMAKE_INSTALL_PREFIX}/doc/ulatencyd
        OPTIONAL)


####################################
##          docs target           ##
add_custom_target(docs)
add_dependencies(docs docs-txt docs-html docs-api)
