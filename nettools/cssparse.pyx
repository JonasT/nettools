
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

import html.parser


cdef int SELECTOR_DEBUG = False


cpdef enable_selector_debugging():
    global SELECTOR_DEBUG
    SELECTOR_DEBUG = True


cpdef disable_selector_debugging():
    global SELECTOR_DEBUG
    SELECTOR_DEBUG = False


cdef class CSSAttribute:
    cdef public str name, value

    def __init__(self, name, value):
        self.name = name.strip()
        self.value = value.strip()
        if self.value.endswith(";"):
            self.value = self.value[:-1]
        if self.value.startswith("'") and self.value.endswith("'"):
            self.value = self.value[1:-1].strip()
        elif self.value.startswith("\"") and self.value.endswith("\""):
            self.value = self.value[1:-1].strip()
        self.value = self.value

    def __repr__(self):
        return "<CSSAttribute " + str(self.name) +\
            ":'" + str(self.value).replace("\\", "\\\\").\
            replace("'", "\\'") + "'>"

    @classmethod
    def parse_from(cls, css_string):
        css_string = css_string.strip()
        if css_string.find(":") <= 0:
            return None
        (left_part, _, right_part) = css_string.partition(":")
        if len(left_part) == 0 or len(right_part) == 0:
            return None
        attribute = CSSAttribute(left_part, right_part)
        if len(attribute.name) == 0 or len(attribute.value) == 0:
            return None
        return attribute


cdef char_is_hex(v):
    v = v.lower()
    return (ord(v) >= ord("a") and ord(v) <= ord("f")) or\
        (ord(v) >= ord("0") and ord(v) <= ord("9"))


cdef is_hex(v):
    if len(v) == 0:
        return False
    i = 0
    while i < len(v):
        if not char_is_hex(v[i]):
            return False
        i += 1
    return True


cpdef parse_css_color(color):
    color = color.lower()
    if color == "red":
        return "#ff0000"
    elif color == "green":
        return "#00ff00"
    elif color == "blue":
        return "#0000ff"
    elif color == "gray" or color == "grey":
        return "#777777"
    elif color == "orange":
        return "#ffee00"
    elif color == "white":
        return "#ffffff"
    elif color == "black":
        return "#000000"
    elif color == "pink":
        return "#ff00aa"
    elif len(color) == 4 and color[0] == "#" and \
            is_hex(color[1:]):
        return "#" + color[1] + color[1] +\
            color[2] + color[2] +\
            color[3] + color[3]
    elif len(color) == 7 and color[0] == "#" and \
            is_hex(color[1:]):
        return color
    return None


cpdef tuple parse_border_attribute(v):
    v = v.strip().split()
    set_type = None
    set_width = None
    set_color = None
    types = ["dashed", "dotted", "solid"]
    for t in types:
        do_continue = True
        while do_continue:
            do_continue = False
            if t in v:
                do_continue = True
                v.remove(t)
                set_type = t
    do_continue = True
    while do_continue:
        do_continue = False
        for i in v:
            _c = parse_css_color(i)
            if _c is not None:
                set_color = _c
                v.remove(i)
                do_continue = True
                break
        for i in v:
            match = False
            for ending in ["px", "rem", "em", "vw", "vh"]:
                try:
                    set_width = str(int(i)) + ending
                    v.remove(i)
                    do_continue = True
                    match = True
                    break
                except (ValueError, TypeError):
                    if i.endswith(ending):
                        try:
                            set_width = str(int(i[:-len(ending)])) + ending
                            v.remove(i)
                            do_continue = True
                            match = True
                            break
                        except (ValueError, TypeError) as e:
                            pass
            if match:
                break
    return (set_type, set_color, set_width)


cpdef csstransform_parse_border(result):
    for bsuffix in ["", "-left", "-top", "-bottom", "-right"]:
        if "border" + bsuffix in result.attributes:
            rule_priority = result.priorities["border" + bsuffix]
            # Parse the "border" rule:
            (border_style, border_color, border_width) = \
                parse_border_attribute(
                    result.attributes["border" + bsuffix].value
                )
            induced_values = {
                "border-style": border_style,
                "border-color": border_color,
                "border-width": border_width,
            }
            # See what the induced values override & add them:
            for induced_vname in induced_values:
                for dir_suffix in ["", "-left", "-top",
                                   "-bottom", "-right"]:
                    if len(bsuffix) > 0 and bsuffix != dir_suffix:
                        continue
                    if induced_vname + dir_suffix in result.attributes and \
                            result.priorities[induced_vname + dir_suffix] <\
                            rule_priority:
                        del(result.attributes[induced_vname + dir_suffix])
                        del(result.priorities[induced_vname + dir_suffix])
                if induced_values[induced_vname] is not None and (
                        bsuffix == "" or
                        induced_vname not in result.attributes
                        ) and (
                        induced_vname + bsuffix not in result.attributes
                        ):
                    result.attributes[induced_vname + bsuffix] =\
                        CSSAttribute(induced_vname + bsuffix,
                                     induced_values[induced_vname])
            # After adding the induced detail attributes, remove "border":
            del(result.attributes["border" + bsuffix])
            del(result.priorities["border" + bsuffix])
    return result


cdef class CSSSelector:
    cdef public list items
    cdef int _specificity
    cdef int applies_any

    def __init__(self, str selector_string):
        selector_string = selector_string.strip()
        self.items = selector_string.split()
        self.applies_any = False
        if len(self.items) == 1 and self.items[0] == "*":
            self.applies_any = True
        self._specificity = 0
        for item in self.items:
            if item == ">" or item == "*":
                continue
            self._specificity += self.get_item_specificity(item)

    @property
    def specificity(self):
        return self._specificity

    @classmethod
    def get_item_specificity(cls, item):
        cdef int specificity_count = 1
        if item.find("]") > 0:
            specificity_count += 10
        item = item.partition("[")[0]
        specificity_count += item.count(".") * 10
        specificity_count += item.count("#") * 100
        return specificity_count

    @classmethod
    def check_item(cls,
                   str item_selector, str item_name,
                   list item_classes=[],
                   str item_id=None):
        item_classes = list(item_classes)
        cdef str detail_constraint = item_selector.partition("[")[2].strip()
        if detail_constraint.endswith("]"):
            detail_constraint = detail_constraint[:-1].strip()
        if len(detail_constraint) > 0:
            # We don't support that yet.
            return False

        item_selector = item_selector.partition("[")[0].strip()

        if item_selector == "*":
            if SELECTOR_DEBUG:
                print("nettools.cssparse.CSSSelector: " +
                      "DEBUG: check_item" +
                      str((item_selector, item_name,
                           item_classes, item_id)) +
                      " -> True"
                )
            return True
        selector_item_name = item_selector
        selector_item_classes = []
        selector_item_id = ""
        while selector_item_name.find(".") >= 0:
            new_class_str = selector_item_name.rpartition(".")[2]
            selector_item_name = selector_item_name.rpartition(".")[0]
            if new_class_str.find("#") > 0:
                selector_name += new_class_str.partition("#")[2]
                new_class_str = new_class_str.partition("#")[0]
            selector_item_classes += [
                c.strip() for c in new_class_str.split(".")
                if len(c.strip()) > 0
            ]
        if selector_item_name.find("#") >= 0:
            selector_item_id = selector_item_name.rpartition("#")[2]
            selector_item_name = selector_item_name.rpartition("#")[0]

        if len(selector_item_name) > 0 and item_name != selector_item_name:
            if SELECTOR_DEBUG:
                print("nettools.cssparse.CSSSelector: " +
                      "DEBUG: check_item" +
                      str((item_selector, item_name, item_classes, item_id)) +
                      " -> False"
                )
            return False
        if len(selector_item_classes) > 0:
            for required_class in selector_item_classes:
                if required_class not in item_classes:
                    if SELECTOR_DEBUG:
                        print("nettools.cssparse.CSSSelector: " +
                              "DEBUG: check_item" +
                              str((item_selector, item_name, item_classes,
                                   item_id)) +
                              " -> False"
                        )
                    return False
        if len(selector_item_id) > 0 and item_id != selector_item_id:
            if SELECTOR_DEBUG:
                print("nettools.cssparse.CSSSelector: " +
                      "DEBUG: check_item" +
                      str((item_selector, item_name, item_classes, item_id)) +
                      " -> False"
                )
            return False
        if SELECTOR_DEBUG:
            print("nettools.cssparse.CSSSelector: " +
                  "DEBUG: check_item" +
                  str((item_selector, item_name, item_classes, item_id)) +
                  " -> True"
            )
        return True


cdef class CSSRule:
    cdef public CSSSelector selector
    cdef public list attributes
    cdef public int occurrence_order

    def __init__(self, str selector_str="*",
                 list attributes=[]):
        self.selector = CSSSelector(selector_str)
        self.attributes = list(attributes)
        self.occurrence_order = -1

    def __repr__(self):
        return "<CSSRule '" +\
            (" ".join(self.selector.items)).replace("'", "'\"'\"'") +\
            "'/" + str(len(self.attributes)) + " attrs>"

    def applies_to_item_chain(self, chain):
        i = len(chain) - 1
        def get_next_parent_info():
            nonlocal i
            i -= 1
            if i > 0:
                return chain[i]
            raise StopIteration("end of parents")
        return self.applies_to_item(
            chain[-1][0],
            chain[-1][1] if len(chain[-1]) >= 2 else "",
            chain[-2][2] if len(chain[-2]) >= 3 else "",
            get_next_parent_info=get_next_parent_info
        )

    def trumps_other_rule(self, rule):
        return (self.get_sorting_id() > rule.get_sorting_id())

    def get_sorting_id(self):
        return int(self.occurrence_order) +\
            int(self.selector.specificity) * 10000000

    def applies_to_item(self,
            str item_name,
            list item_classes=[],
            str item_id="",
            object get_next_parent_info=None
            ):
        item_classes = list(item_classes)
        if self.selector.applies_any:
            return True
        if len(self.selector.items) == 0:
            return False
        cdef int first_item = True
        cdef tuple item_info

        cdef int require_direct_descendant = False
        cdef int i = len(self.selector.items) 
        while i > 0:
            i -= 1
            if first_item:
                item_info = (item_name, item_classes, item_id)
                if not self.selector.check_item(
                        self.selector.items[i],
                        item_name,
                        item_classes=item_classes,
                        item_id=item_id
                        ):
                    return False
                require_direct_descendant = False
            elif self.selector.items[i] == ">":
                require_direct_descendant = True
                continue
            else:
                while True:
                    try:
                        parent = get_next_parent_info()
                    except (StopIteration, ValueError):
                        parent = None
                    if parent is None:
                        return False
                    item_info = (parent[0],
                                 list(parent[1]) if len(parent) >= 2 else [],
                                 parent[2] if len(parent) >= 3 else "")
                    if not self.selector.check_item(
                            self.selector.items[i],
                            item_info[0],
                            item_classes=item_info[1], item_id=item_info[2]
                            ):
                        if require_direct_descendant:
                            return False
                    else:
                        break
                require_direct_descendant = False
                continue
        return True


cdef class CSSAttributeQueryResult:
    cdef public dict attributes
    cdef public dict priorities

    def __init__(self, attributes, rule_priorities):
        self.attributes = attributes
        self.priorities = rule_priorities


cdef class CSSRulesetCollection:
    """ Members are in cssparse.pxd """

    def __init__(self):
        self.rules = []

    def __repr__(self):
        return "<CSSRuleCollection" + str(self.rules) + ">"

    def get_item_attributes(self,
            str item_name,
            list item_classes=[], str item_id="",
            object get_next_parent_info=None,
            int nondirectional_can_override_directional=True,
            list transform_funcs=[csstransform_parse_border],
            ):
        directionals = ("-left", "-right", "-top", "-bottom")
        item_classes = list(item_classes)
        cdef dict result_attributes = {}
        cdef int rule_id = -1
        for rule in self.rules:
            rule_id += 1
            if rule.occurrence_order < 0:
                rule.occurrence_order = rule_id
            if rule.applies_to_item(item_name, item_classes, item_id,
                                    get_next_parent_info=
                                        get_next_parent_info
                                    ):
                for attr in rule.attributes:
                    if SELECTOR_DEBUG:
                        print("nettools.cssparse.CSSRulesetCollection: " +
                              "DEBUG: rule's applies_to_item" +
                              str((item_name, item_classes, item_id,
                                   get_next_parent_info)) +
                              "=True, rule=" + str(rule))

                    # Collect all the attributes that could clash with this:
                    clashing_attributes = []
                    if attr.name in result_attributes and \
                            result_attributes[attr.name][1] != rule:
                        clashing_attributes.append(
                            result_attributes[attr.name]
                        )
                    if nondirectional_can_override_directional and \
                            attr.name.endswith(directionals) and \
                            attr.name.rpartition("-")[0] in \
                                result_attributes and \
                            result_attributes[
                                attr.name.rpartition("-")[0]
                            ][1] != rule:
                        clashing_attributes.append(result_attributes[
                            attr.name.rpartition("-")[0]
                        ])
                    if nondirectional_can_override_directional and \
                            not attr.name.endswith(directionals) and \
                            len([attr.name + d for d in directionals
                                 if attr.name + d in result_attributes]) > 0:
                        for d in directionals:
                            if attr.name + d in result_attributes and \
                                    result_attributes[
                                        attr.name + d
                                    ][1] != rule:
                                clashing_attributes.append(result_attributes[
                                    attr.name + d
                                ])

                    # Bail out of setting this attribute if it's overridden:
                    must_be_ignored = False
                    for (old_attr, old_rule) in clashing_attributes:
                        if rule != old_rule and not \
                                rule.trumps_other_rule(old_rule):
                            if SELECTOR_DEBUG:
                                print("nettools.cssparse." +
                                      "CSSRulesetCollection: " +
                                      "DEBUG: rule sets IGNORED attribute: " +
                                      str(attr.name) + "='" +
                                      str(attr.value) +
                                      "'   (we already got more " +
                                      "specific rule: " +
                                      str(old_rule) + "/attribute " +
                                      str(old_attr) + ")")
                            must_be_ignored = True
                            break
                    if must_be_ignored:
                        continue

                    # Debug-announce we'll set the attribute:
                    if SELECTOR_DEBUG and len(clashing_attributes) > 0:
                        print("nettools.cssparse.CSSRulesetCollection: " +
                              "DEBUG: rule sets OVERRIDING attribute: " +
                              str(attr.name) + "='" +
                              str(attr.value) + "'   (overrides " +
                              str([(c[0].name, c[1]) for c in
                                   clashing_attributes]) + ")")
                    elif SELECTOR_DEBUG:
                        print("nettools.cssparse.CSSRulesetCollection: " +
                              "DEBUG: rule sets NEW attribute: " +
                              str(attr.name) + "='" +
                              str(attr.value) + "'")
                    # Set actual new value:
                    result_attributes[attr.name] = (attr, rule)

                    # Make sure overriden values, if any, are removed:
                    for c in clashing_attributes:
                        if c[0].name != attr.name and \
                                c[0].name in result_attributes:
                            del(result_attributes[c[0].name])

        result = CSSAttributeQueryResult(
            {v[0].name: v[0] for v in result_attributes.values()},
            {v[0].name: v[1].get_sorting_id()
             for v in result_attributes.values()},
        )
        #if SELECTOR_DEBUG:
        #    print("nettools.cssparse.CSSRulesetCollection: " +
        #          "DEBUG: ruleset attributes result: " +
        #          str(result))
        for transform_func in transform_funcs:
            result = transform_func(result)
        return result


cpdef str extract_string_without_comments(str string):
    cdef str result = ""
    cdef str c
    cdef size_t i = 0
    cdef set whitespace = {" ", "\t", "\n", "\r"}
    cdef str in_quote = ""
    cdef int backspace_escaped = False
    cdef ssize_t last_comment_end = -1
    cdef size_t slen = len(string)
    while i < slen:
        c = string[i]
        if c in whitespace:
            i += 1
            continue
        if len(in_quote) > 0:
            if backspace_escaped:
                backspace_escaped = False
                i += 1
                continue
            if c == "\\":
                backspace_escaped = True
                i += 1
                continue
            if c == in_quote:
                in_quote = ""
                i += 1
                continue
            i += 1
            continue
        elif c in {"'", "\""}:
            in_quote = c
            i += 1
            continue
        if c == "/" and string[i:i + 2] == "/*":
            result += string[last_comment_end + 1:i]
            i += 2
            while i < slen and (
                    string[i] != "*" or not string[i:i + 2] == "*/"
                    ):
                i += 1
            last_comment_end = i + 1
            i += 2
            continue
        i += 1
    # Ending:
    result += string[last_comment_end + 1:]
    return result


cpdef list extract_rule_strings(str string):
    string = extract_string_without_comments(string)
    cdef str c
    cdef int i = 0
    cdef list rules
    rules = [] 
    cdef set whitespace = {" ", "\t", "\n", "\r"}
    cdef int rule_started_at = -1
    cdef int bracket_nesting_depth = 0
    cdef int slen = len(string)
    while i < slen:
        c = string[i]
        if rule_started_at < 0:
            rule_started_at = i
            bracket_nesting_depth = 0
        elif c == "{":
            bracket_nesting_depth += 1
        elif c == "}":
            bracket_nesting_depth = max(0, bracket_nesting_depth - 1)
            if bracket_nesting_depth == 0:
                rules.append(
                    string[max(0, rule_started_at):i + 1].\
                        replace("\n", " ").replace("\r", " ").strip()
                )
            rule_started_at = -1
        i += 1
    return rules


cpdef parse_css_inline_attributes(str css_string):
    fragments = []
    cdef int i = 0
    current_item_start = 0
    bracket_nesting = 0
    backslash_quoted = False
    string_quoting = None
    while i < len(css_string):
        if css_string[i] == ";" and bracket_nesting == 0 and \
                string_quoting == None:
            fragments.append(css_string[
                current_item_start:i + 1])
            current_item_start = i + 1
            backslash_quoted = False
            i += 1
            continue
        elif string_quoting is None and (
                css_string[i] == "(" or css_string[i] == "{"):
            bracket_nesting += 1
        elif string_quoting is None and (
                css_string[i] == ")" or css_string[i] == "}"):
            bracket_nesting -= 1
        elif css_string[i] == "\\":
            backslash_quoted = True
            i += 1
            continue
        elif backslash_quoted:  # stop elif fall-through:
            backslash_quoted = False
        elif css_string[i] == string_quoting:
            string_quoting = None
        elif string_quoting == None and css_string[i] == "'":
            string_quoting = "'"
        elif string_quoting == None and css_string[i] == "\"":
            string_quoting = "\""
        backslash_quoted = False
        i += 1
    fragments.append(css_string[current_item_start:i])
    css_items = []
    for item in fragments:
        item = item.strip()
        attribute = CSSAttribute.parse_from(item)
        if attribute != None:
            css_items.append(attribute)
    return css_items


cpdef CSSRulesetCollection parse_inline(str css):
    css = extract_string_without_comments(css)
    cdef list items = parse_css_inline_attributes(css)
    rule = CSSRule()
    rule.attributes = items
    ruleset = CSSRulesetCollection()
    return ruleset


cpdef CSSRulesetCollection parse(str css):
    cdef CSSRulesetCollection result
    result = CSSRulesetCollection()
    cdef list rule_strings = extract_rule_strings(css)
    for rule_str in rule_strings:
        rule_str = rule_str.strip()
        rule_selector_str = rule_str.partition("{")[0].strip()
        rule_contents = rule_str.partition("{")[2].strip()
        if rule_contents.endswith("}"):
            rule_contents = rule_contents[:-1].strip()
        if len(rule_selector_str) == 0 or len(rule_contents) == 0:
            continue
        attributes = parse_css_inline_attributes(rule_contents)
        if len(attributes) == 0:
            continue
        rule_selectors = [
            c.strip() for c in rule_selector_str.split(",")
            if len(c.strip()) > 0
        ]
        for rule_selector in rule_selectors:
            result.rules.append(CSSRule(
                selector_str=rule_selector,
                attributes=attributes
            ))
    return result
