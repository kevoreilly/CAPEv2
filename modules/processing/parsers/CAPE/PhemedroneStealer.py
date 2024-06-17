# Phemedrone Stealer config extractor by @tccontre18 - Br3akp0int
# https://github.com/tccontre/KnowledgeBase/blob/main/malware_re_tools/phemdrone_cfg_extractor/phemdrone_extractor_s.py

import abc

CilMethodBodyReaderBase = abc.ABC

try:
    import dnfile
    from dnfile.enums import MetadataTables

    HAVE_DNFILE = True
except ImportError:
    HAVE_DNFILE = False

try:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.body.reader import CilMethodBodyReaderBase
    from dncil.cil.error import MethodBodyFormatError
    from dncil.clr.token import InvalidToken, StringToken, Token

    HAVE_DNCIL = True
except ImportError:
    print("Missed dependency: poetry run pip install dncil")
    HAVE_DNCIL = False


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        """ """
        self.pe = pe
        self.offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        """ """
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self):
        """ """
        return self.offset

    def seek(self, offset):
        """ """
        self.offset = offset
        return self.offset


class DnfileParse:
    DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}

    @staticmethod
    def read_dotnet_user_string(pe, token):
        """read user string from #US stream"""
        try:
            user_string = pe.net.user_strings.get(token.rid)
        except UnicodeDecodeError:
            return InvalidToken(token.value)

        if user_string is None:
            return InvalidToken(token.value)

        return user_string.value

    @staticmethod
    def resolve_token(pe, token):
        """ """
        if isinstance(token, StringToken):
            return DnfileParse.read_dotnet_user_string(pe, token)

        table_name = DnfileParse.DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
        if not table_name:
            # table_index is not valid
            return InvalidToken(token.value)

        table = getattr(pe.net.mdtables, table_name, None)
        if table is None:
            # table index is valid but table is not present
            return InvalidToken(token.value)

        try:
            return table.rows[token.rid - 1]
        except IndexError:
            # table index is valid but row index is not valid
            return InvalidToken(token.value)

    @staticmethod
    def read_method_body(pe, row):
        """ """
        return CilMethodBody(DnfileMethodBodyReader(pe, row))

    @staticmethod
    def format_operand(pe, operand):
        """ """
        if isinstance(operand, Token):
            operand = DnfileParse.resolve_token(pe, operand)

        if isinstance(operand, str):
            return f'"{operand}"'
        elif isinstance(operand, int):
            return hex(operand)
        elif isinstance(operand, list):
            return f"[{', '.join(['({:04X})'.format(x) for x in operand])}]"
        elif isinstance(operand, dnfile.mdtable.MemberRefRow):
            if isinstance(operand.Class.row, (dnfile.mdtable.TypeRefRow,)):
                return f"{str(operand.Class.row.TypeNamespace)}.{operand.Class.row.TypeName}::{operand.Name}"
        elif isinstance(operand, dnfile.mdtable.TypeRefRow):
            return f"{str(operand.TypeNamespace)}.{operand.TypeName}"
        elif isinstance(operand, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
            return f"{operand.Name}"
        elif operand is None:
            return ""

        return str(operand)

    @staticmethod
    def get_instruction_text(pe, insn):
        return (
            "{:04X}".format(insn.offset)
            + "    "
            + f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
            + f"{str(insn.opcode) : <15}"
            + DnfileParse.format_operand(pe, insn.operand)
        )


def check_next_inst(pe, body, DnfileParse, index):

    str_list = []
    for i in range(1, len(body.instructions) << 2):
        if index + i >= len(body.instructions):
            break
            return None
        else:
            next_inst = body.instructions[index + i]
            next_inst_ = DnfileParse.get_instruction_text(pe, next_inst)
            if str(next_inst.opcode) == "ldstr":
                str_list.append(DnfileParse.resolve_token(pe, next_inst.operand))
            elif str(next_inst.opcode) == "stsfld":
                return (next_inst_.split(" ")[-1]), str_list


def extract_config(data):
    config_dict = {}
    if not HAVE_DNFILE or not HAVE_DNCIL:
        return
    try:
        pe = dnfile.dnPE(data=data)
    except dnfile.PEFormatError:
        return
    for row in pe.net.mdtables.MethodDef:
        # skip methods that do not have a method body
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            continue
        try:
            body = DnfileParse.read_method_body(pe, row)
        except MethodBodyFormatError:
            continue
        if not body.instructions:
            continue
        if row.Name == ".cctor":
            index = 0
            if len(body.instructions) >= 20 and str(body.instructions[0].opcode) == "ldstr":
                for index in range(0, len(body.instructions)):
                    value_data = ""
                    config_field_name = ""
                    inst = body.instructions[index]
                    inst_ = DnfileParse.get_instruction_text(pe, inst)
                    if str(inst.opcode) == "ldstr":
                        value_data = DnfileParse.resolve_token(pe, inst.operand)
                        config_field_name, str_list = check_next_inst(pe, body, DnfileParse, index)
                        if config_field_name is not None and config_field_name not in config_dict:
                            str_list.insert(0, value_data)
                            config_dict[config_field_name] = ", ".join(str_list)
                        else:
                            pass
                    if "ldc.i4." in str(inst.opcode):
                        if inst_.split(".")[-1].strip() == "0":
                            value_data = "False"
                            config_field_name, str_list = check_next_inst(pe, body, DnfileParse, index)
                            config_dict[config_field_name] = value_data
                        elif inst_.split(".")[-1].strip() == "1":
                            value_data = "True"
                            config_field_name, str_list = check_next_inst(pe, body, DnfileParse, index)
                            config_dict[config_field_name] = value_data
                        else:
                            value_data = inst_.split(".")[-1].strip()
                            config_field_name, str_list = check_next_inst(pe, body, DnfileParse, index)
                            config_dict[config_field_name] = value_data
    return config_dict
