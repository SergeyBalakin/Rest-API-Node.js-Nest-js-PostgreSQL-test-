import { IsString, IsNumber } from 'class-validator'

export class AddRoleDto {
  @IsString({ message: 'Должно быть строкой' })
  readonly value: string
  @IsNumber({}, { message: 'Должно быть строкой' })
  readonly userId: number
}
