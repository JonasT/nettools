'''
nettools - Copyright 2019 python nettools team, see AUTHORS.md

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
'''

cdef class CSSSelectorItem:
    cdef public str content
    cdef object tag_constraint, classes_constraint
    cdef object id_constraint
    cdef list attribute_constraints
    cdef public list colon_special_constraints


cdef class CSSRulesetCollection:
    cdef public list rules


cpdef enable_selector_debugging()


cpdef disable_selector_debugging()


cpdef tuple parse_border_attribute(v)


cpdef csstransform_parse_border(result)


cpdef CSSRulesetCollection parse_inline(str css)


cpdef CSSRulesetCollection parse(str css)


cpdef parse_css_color(color)


cpdef parse_css_inline_attributes(str css_string)


cpdef str extract_string_without_comments(str string)
