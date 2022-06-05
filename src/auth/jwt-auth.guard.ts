import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common'
import { Observable } from 'rxjs'
import { JwtService } from '@nestjs/jwt'

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext
  ): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest()
    try {
      const authHeder = req.headers.authorization
      const bearer = authHeder.split(' ')[0]
      const token = authHeder.split(' ')[1]

      if (bearer !== 'Bearer' || !token) {
        throw new UnauthorizedException({
          message: 'Пользователь не авторизован',
        })
      }
      const user = this.jwtService.verify(token)
      req.user = user
      return true
    } catch (e) {
      console.log(e)
      throw new UnauthorizedException({
        message: 'Пользователь не авторизован',
      })
    }
  }
}
