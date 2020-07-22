#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 wlz <wlz@kyria>
#
# Distributed under terms of the MIT license.

import idaapi
import idautils
import idc


GOLANG_FUNC    = "golang_rev:golang_func"
GOLANG_STRING  = "golang_rev:golang_string"
RENAME_POINTER = 'golang_rev:rename_pointer'

class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == GOLANG_STRING:
            self.set_string()
        elif self.action == GOLANG_FUNC:
            self.set_function()
        elif self.action == RENAME_POINTER:
            self.rename_pointer()
        else:
            return 0 
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
    def set_string(self):
        start = idc.here()
        str_len = idaapi.ask_long(0, "string len...")
        if str_len:
            idc.MakeStr(start, start + str_len)
        return 1

    def rename_pointer(self):
        name = 'p_{}'.format(idc.Name(idc.Qword(idc.here())))
        idc.MakeName(idc.here(), name)

    def set_function(self):
        try: 
            base  = idautils.ida_segment.get_segm_by_name('.gopclntab').start_ea
        except:
            print("Cannot get segment .gopclntab!")
            return 0
        ea    = base + 8
        len   = idc.Qword(ea) * 8 * 2
        ptr   = base + 8 + 8
        end   = base + len
        while ptr <= end:
            idc.MakeQword(ptr)
            func_addr = idc.Qword(ptr)
            idc.MakeQword(ptr + 8)
            name_offset = idc.Qword(ptr + 8)
            name_addr   = idc.Dword(base + 8 + name_offset) + base
            name        = idc.GetString(name_addr)
            name = name.replace('.','_').replace("<-",'_chan_left_').replace('*','_ptr_').replace('-','_').replace(';','').replace('"','').replace('\\\\','')
            name = name.replace('(','').replace(')','').replace('/','_').replace(' ','_').replace(',','comma').replace('{','').replace('}','')
            idc.MakeName(func_addr, name)
            print(name)
            print(ptr)
            ptr += 16
        idc.jumpto(idc.get_name_ea_simple('main_main'))
        return 1


class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)

        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1) or idc.get_item_size(idc.get_screen_ea()) > 1:
                idaapi.attach_action_to_popup(form, popup, GOLANG_FUNC, None)
                idaapi.attach_action_to_popup(form, popup, GOLANG_STRING, None)
                idaapi.attach_action_to_popup(form, popup, RENAME_POINTER, None)



class Golang_Rev(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Golang_Rev"
 
    help = ""
    wanted_name = "Golang_Rev"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

        global ARCH
        global BITS
        ARCH = idaapi.ph_get_id()
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            BITS = 64
        elif info.is_32bit():
            BITS = 32
        else:
            BITS = 16

        print("Golang_Rev plugin has been loaded.")

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(GOLANG_STRING, "Set golang string", menu_action_handler_t(GOLANG_STRING), None, None, 9),
            idaapi.action_desc_t(GOLANG_FUNC, "Set golang function", menu_action_handler_t(GOLANG_FUNC), None, None, 9),
            idaapi.action_desc_t(RENAME_POINTER, "Set pointer", menu_action_handler_t(RENAME_POINTER), None, None, 9),
        )
        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if hasattr(self, "ui_hook"):
            self.ui_hook.unhook()

        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)



def PLUGIN_ENTRY():
    return Golang_Rev()